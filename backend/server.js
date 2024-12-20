//require("dotenv").config(); // Carrega as variáveis do arquivo .env
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
require("dotenv").config(); // Carrega as variáveis do arquivo .env
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const path = require("path");
const axios = require("axios");
const cors = require("cors");

const app = express();
const SECRET = "seu_token_secreto";

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Token da API DoBank
const DOBANK_API_TOKEN = "LhHwUgR7RBqrWkZ6YMWjpk6wvlLjM6CqyaZK1P9Sr6lyS5oq0vKBiwjQUuK9XILajo0jK5WgHCd1qgMHbQKmbIByS5iyvkR20EbkhLgZaYjykKPZOVowZTXNN3ytSXwK8ax3BkeU2QIBagg1RVQGbgi96XzFgbiUKNAWLYhCuEfnBoqLFUedhhArQ17GwuIirUZI8mSq";

// Configuração do banco de dados
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log("Conectado ao banco de dados");
});

// Configurar pasta de arquivos estáticos
app.use(express.static(path.join(__dirname, "../frontend")));

// Rotas para as páginas HTML
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/login.html"));
});

app.get("/cadastro", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/cadastro.html"));
});

app.get("/recarregar", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/recarregar.html"));
});

// Função para gerar código de indicação único
function gerarReferralCode() {
  return "ref_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
}

// Rota de cadastro
app.post("/register", async (req, res) => {
  const { phone, password, referral_code } = req.body;

  if (!phone || !password) return res.status(400).json({ error: "Dados inválidos" });

  const hashedPassword = await bcrypt.hash(password, 10);

  // Se houver referral_code no cadastro, buscamos quem o possui
  let referred_by = null;
  if (referral_code) {
    try {
      const [rows] = await db.promise().query("SELECT id FROM users WHERE referral_code = ?", [referral_code]);
      if (rows.length > 0) {
        referred_by = rows[0].id;
      } else {
        return res.status(400).json({ error: "Código de indicação inválido." });
      }
    } catch (error) {
      console.error("Erro ao buscar referral_code:", error);
      return res.status(500).json({ error: "Erro interno ao buscar indicação." });
    }
  }

  const newReferralCode = gerarReferralCode();
  const query = "INSERT INTO users (phone, password, referral_code, referred_by, saldo) VALUES (?, ?, ?, ?, 0)";
  db.query(query, [phone, hashedPassword, newReferralCode, referred_by], (err) => {
    if (err) return res.status(500).json({ error: "Erro ao cadastrar" });
    res.status(201).json({ message: "Usuário registrado com sucesso" });
  });
});

// Rota de login
app.post("/login", (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ error: "Dados inválidos" });
  }

  const query = "SELECT * FROM users WHERE phone = ?";
  db.query(query, [phone], async (err, results) => {
    if (err) return res.status(500).json({ error: "Erro ao buscar usuário" });
    if (results.length === 0) return res.status(404).json({ error: "Usuário não encontrado" });

    const user = results[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) return res.status(401).json({ error: "Senha incorreta" });

    const token = jwt.sign({ id: user.id, phone: user.phone }, SECRET, { expiresIn: "1h" });
    res.status(200).json({
      message: "Login bem-sucedido",
      token,
      user_id: user.id // Retorna o user_id para o frontend
    });
  });
});

// Função para adicionar saldo a um usuário
function adicionarSaldo(userId, valor) {
  return new Promise((resolve, reject) => {
    const q = "UPDATE users SET saldo = saldo + ? WHERE id = ?";
    db.query(q, [valor, userId], (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

// Função para verificar se é o primeiro investimento confirmado
async function ehPrimeiroInvestimento(userId) {
  const [rows] = await db.promise().query(
    "SELECT COUNT(*) as total FROM recargas WHERE user_id = ? AND status = 'confirmado'",
    [userId]
  );
  // Se após confirmar essa recarga, total = 1, então é o primeiro investimento
  return rows[0].total === 1;
}

// Função para pagar comissões de referrals
async function pagarComissoesReferrals(userId, amount) {
  // Nível 1
  const [uRows] = await db.promise().query("SELECT referred_by FROM users WHERE id = ?", [userId]);
  if (uRows.length === 0) return;
  const nivel1 = uRows[0].referred_by;
  if (!nivel1) return; // usuário não foi indicado, sem comissões

  // Paga 37% para o nível 1
  const bonusN1 = amount * 0.37;
  await adicionarSaldo(nivel1, bonusN1);

  // Nível 2
  const [n1Rows] = await db.promise().query("SELECT referred_by FROM users WHERE id = ?", [nivel1]);
  const nivel2 = n1Rows[0]?.referred_by;
  if (nivel2) {
    const bonusN2 = amount * 0.01;
    await adicionarSaldo(nivel2, bonusN2);

    // Nível 3
    const [n2Rows] = await db.promise().query("SELECT referred_by FROM users WHERE id = ?", [nivel2]);
    const nivel3 = n2Rows[0]?.referred_by;
    if (nivel3) {
      const bonusN3 = amount * 0.01;
      await adicionarSaldo(nivel3, bonusN3);
    }
  }
}
app.post("/comprar", async (req, res) => {
    const { product_id } = req.body;
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ error: "Token não fornecido." });
    }
  
    try {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, SECRET);
      const userId = decoded.id;
  
      // Busca o produto
      const [prodRows] = await db.promise().query("SELECT * FROM products WHERE id = ?", [product_id]);
      if (prodRows.length === 0) {
        return res.status(404).json({ error: "Produto não encontrado." });
      }
      const product = prodRows[0];
  
      // Verifica saldo do usuário
      const [userRows] = await db.promise().query("SELECT saldo FROM users WHERE id = ?", [userId]);
      if (userRows.length === 0) {
        return res.status(404).json({ error: "Usuário não encontrado." });
      }
  
      let saldoAtual = parseFloat(userRows[0].saldo);
      if (saldoAtual < parseFloat(product.price)) {
        return res.status(400).json({ error: "Saldo insuficiente." });
      }
  
      // Desconta do saldo
      saldoAtual -= parseFloat(product.price);
      await db.promise().query("UPDATE users SET saldo = ? WHERE id = ?", [saldoAtual, userId]);
  
      // Registra a compra
      const purchaseDate = new Date();
      const endDate = new Date();
      endDate.setDate(purchaseDate.getDate() + product.duration_days);
  
      await db.promise().query(`
        INSERT INTO user_products (user_id, product_id, purchase_date, end_date, daily_income)
        VALUES (?, ?, ?, ?, ?)
      `, [userId, product.id, purchaseDate, endDate, product.daily_income]);
  
      res.json({ message: "Produto comprado com sucesso." });
  
    } catch (error) {
      console.error("Erro ao comprar produto:", error);
      res.status(500).json({ error: "Erro interno ao comprar o produto." });
    }
  });
  
  async function atualizarAcumulacao() {
    const [users] = await db.promise().query("SELECT id FROM users");
    for (const user of users) {
      const userId = user.id;
      // Busca produtos ativos do usuário
      const [prodRows] = await db.promise().query(`
        SELECT * FROM user_products
        WHERE user_id = ? AND end_date >= NOW()
      `, [userId]);
  
      let acumulacaoDia = 0;
      for (const up of prodRows) {
        // Verifica quantos dias já se passaram desde a purchase_date
        const hoje = new Date();
        const diffTime = Math.abs(hoje - new Date(up.purchase_date));
        const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
        
        // multiplica daily_income pelos dias já decorridos, ou total_incomes. Mas se fizer isso todo dia, você precisará saber o quanto já foi adicionado.
        // Alternativamente, você pode simplesmente adicionar o daily_income uma vez por dia.
        
        // Aqui é só um exemplo simplificado de adicionar a renda do dia atual:
        acumulacaoDia += parseFloat(up.daily_income);
      }
  
      // Soma o acumulacaoDia no accumulation do usuário
      await db.promise().query("UPDATE users SET accumulation = accumulation + ? WHERE id = ?", [acumulacaoDia, userId]);
    }
  }
  app.get("/meus-produtos", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });
    try {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, SECRET);
      const userId = decoded.id;
  
      db.query(`
        SELECT (SELECT COUNT(*) FROM user_products WHERE user_id = ? AND end_date >= NOW()) AS total_produtos,
               accumulation
        FROM users
        WHERE id = ?
      `, [userId, userId], (err, results) => {
        if (err) {
          console.error("Erro ao buscar produtos:", err);
          return res.status(500).json({ error: "Erro ao buscar dados" });
        }
  
        if (results.length === 0) return res.status(404).json({ error: "Usuário não encontrado" });
  
        const { total_produtos, accumulation } = results[0];
        res.json({ total_produtos, accumulation });
      });
    } catch (error) {
      res.status(401).json({ error: "Token inválido" });
    }
  });

  app.post("/fazer-checkin", async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: "Token não fornecido." });
    }

    try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET);
        const userId = decoded.id;

        // Verifica se o usuário já fez check-in hoje
        const [checkinToday] = await db.promise().query(
            "SELECT * FROM checkins WHERE user_id = ? AND date = CURDATE()",
            [userId]
        );

        if (checkinToday.length > 0) {
            return res.status(400).json({ error: "Check-in já realizado hoje." });
        }

        // Registra o check-in e adiciona R$ 5 no acumulo
        await db.promise().query(
            "INSERT INTO checkins (user_id, date, amount) VALUES (?, CURDATE(), 5.00)",
            [userId]
        );

        await db.promise().query(
            "UPDATE users SET accumulation = accumulation + 5.00 WHERE id = ?",
            [userId]
        );

        // Busca os dados atualizados
        const [[user]] = await db.promise().query(
            "SELECT accumulation FROM users WHERE id = ?",
            [userId]
        );

        res.status(200).json({
            message: "Check-in realizado com sucesso!",
            bonus: 5.00,
            accumulation: parseFloat(user.accumulation),
        });
    } catch (error) {
        console.error("Erro ao fazer check-in:", error.message);
        res.status(500).json({ error: "Erro ao realizar check-in." });
    }
});
    app.get("/checkin-status", async (req, res) => {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ error: "Token não fornecido." });
        }

        try {
            const token = authHeader.split(" ")[1];
            const decoded = jwt.verify(token, SECRET);
            const userId = decoded.id;

            // Verifica se já fez check-in hoje
            const [checkinToday] = await db.promise().query(
                "SELECT * FROM checkins WHERE user_id = ? AND date = CURDATE()",
                [userId]
            );

            const [[user]] = await db.promise().query(
                "SELECT accumulation FROM users WHERE id = ?",
                [userId]
            );

            res.status(200).json({
                bonus: 5.00,
                dias_consecutivos: checkinToday.length > 0 ? 1 : 0,
                accumulation: parseFloat(user.accumulation),
            });
        } catch (error) {
            console.error("Erro ao consultar check-in:", error.message);
            res.status(500).json({ error: "Erro ao consultar status de check-in." });
        }
    });


    // Rota para solicitar saque
    app.post("/solicitar-saque", async (req, res) => {
        const { amount, bank_name, agency, account } = req.body;
        const authHeader = req.headers.authorization;
    
        if (!authHeader) {
        return res.status(401).json({ error: "Token não fornecido." });
        }
    
        try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, SECRET);
        const userId = decoded.id;
    
        // Verifica se os dados obrigatórios estão presentes
        if (!amount || amount <= 0 || !bank_name || !agency || !account) {
            return res.status(400).json({ error: "Dados inválidos." });
        }
    
        // Busca o saldo do usuário
        const [user] = await db.promise().query("SELECT saldo FROM users WHERE id = ?", [userId]);
        if (user.length === 0) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }
    
        const userSaldo = parseFloat(user[0].saldo);
    
        // Verifica se o saldo é suficiente
        const taxa = amount * 0.15; // 15% de imposto
        const valorFinal = amount - taxa;
    
        if (userSaldo < amount) {
            return res.status(400).json({ error: "Saldo insuficiente." });
        }
    
        // Atualiza o saldo do usuário no banco
        await db.promise().query("UPDATE users SET saldo = saldo - ? WHERE id = ?", [amount, userId]);
    
        // Chama a API do Dobank para processar o pagamento
        const dobResponse = await axios.post("https://dobank.com.br/api/pagamento", {
            token: DOBANK_API_TOKEN,
            lote: Date.now(), // Identificador único para o lote
            beneficiaries: [
            {
                banco: bank_name,
                agencia: agency,
                conta: account,
                valor: valorFinal.toFixed(2), // Valor líquido a ser transferido
            },
            ],
        });
    
        const pagamento = dobResponse.data;
    
        // Salva o saque no banco de dados
        await db.promise().query(
            `INSERT INTO saques (user_id, amount, bank_name, agency, account, status, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [userId, valorFinal, bank_name, agency, account, "pendente"]
        );
    
        res.status(200).json({ message: "Saque solicitado com sucesso.", lote: pagamento.lote });
        } catch (error) {
        console.error("Erro ao processar saque:", error.message);
        res.status(500).json({ error: "Erro ao processar saque." });
        }
    });
  
  


app.post("/atualizar-status-saque", async (req, res) => {
    const { saque_id, status } = req.body;

    try {
        // Atualizar o status do saque
        await db.promise().query("UPDATE saques SET status = ? WHERE id = ?", [status, saque_id]);

        res.status(200).json({ message: "Status do saque atualizado com sucesso." });

    } catch (error) {
        console.error("Erro ao atualizar status do saque:", error.message);
        return res.status(500).json({ error: "Erro ao atualizar status do saque." });
    }
});

// Rota de recarga
app.post("/recarregar", async (req, res) => {
  const { amount, method_code } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não fornecido." });
  }

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);
    const userId = decoded.id;

    if (!amount || amount <= 0 || !method_code) {
      return res.status(400).json({ error: "Valor ou método inválido." });
    }

    // Chama a API externa para gerar QR Code PIX
    const response = await axios.post("https://dobank.com.br/api/recebimento", {
      token: DOBANK_API_TOKEN,
      amount: amount,
      method_code: method_code,
    });

    const { txid, qrcode, copiaecola, valorcobrado } = response.data;

    if (!txid || !qrcode || !copiaecola) {
      return res.status(500).json({ error: "Dados incompletos retornados pela API." });
    }

    // Salva no banco de dados com status "pendente"
    const insertQuery = `
        INSERT INTO recargas (amount, method_code, txid, qrcode, copiaecolar, user_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(insertQuery, [amount, method_code, txid, qrcode, copiaecola, userId, 'pendente'], (err) => {
      if (err) {
        console.error("Erro ao salvar no banco:", err);
        return res.status(500).json({ error: "Erro ao salvar no banco." });
      }

      // Responde com os dados PIX
      res.status(200).json({
        message: "Recarga criada com sucesso.",
        qrcode: qrcode,
        copiaecola: copiaecola,
        valor_cobrado: valorcobrado,
        txid: txid
      });
    });

  } catch (error) {
    console.error("Erro na recarga:", error.message);
    return res.status(500).json({ error: "Erro ao processar a recarga." });
  }
});

// Rota para confirmar pagamento
app.post("/confirmar-pagamento", async (req, res) => {
  const { txid } = req.body;

  if (!txid) {
    return res.status(400).json({ error: "TXID não fornecido." });
  }

  try {
    // Verifica a recarga com o TXID e o status pendente
    const [results] = await db.promise().query(
      "SELECT * FROM recargas WHERE txid = ? AND status = 'pendente'",
      [txid]
    );

    if (results.length === 0) {
      return res.status(404).json({ error: "Recarga não encontrada ou já confirmada." });
    }

    const recarga = results[0];

    // Atualiza o status para "confirmado"
    await db.promise().query("UPDATE recargas SET status = 'confirmado' WHERE txid = ?", [txid]);

    // Adiciona o saldo ao usuário
    await adicionarSaldo(recarga.user_id, recarga.amount);

    // Verifica se é o primeiro investimento confirmado
    const primeiro = await ehPrimeiroInvestimento(recarga.user_id);
    if (primeiro) {
      // Pagar comissões de indicação
      await pagarComissoesReferrals(recarga.user_id, recarga.amount);
    }

    res.status(200).json({ message: "Pagamento confirmado, saldo atualizado e comissões pagas (se aplicável)." });

  } catch (error) {
    console.error("Erro ao confirmar pagamento:", error.message);
    return res.status(500).json({ error: "Erro ao confirmar pagamento." });
  }
});

// Rota para consultar o saldo do usuário via token
app.post("/saldo", (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(401).json({ error: "Token não fornecido." });

  try {
    const decoded = jwt.verify(token, SECRET);
    const userId = decoded.id;

    const query = `
      SELECT IFNULL(SUM(amount), 0) AS saldo 
      FROM recargas 
      WHERE user_id = ?
        AND status = 'confirmado'
    `;
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error("Erro ao buscar saldo:", err);
        return res.status(500).json({ error: "Erro ao buscar saldo." });
      }

      const saldo = parseFloat(results[0].saldo) || 0;
      res.status(200).json({ saldo });
    });
  } catch (error) {
    console.error("Erro na autenticação:", error.message);
    res.status(401).json({ error: "Token inválido." });
  }
});

// Rota para consultar o saldo por user_id (ex: back-office)
app.get("/saldo/:user_id", (req, res) => {
  const { user_id } = req.params;

  // Consulta ao banco para somar todas as recargas confirmadas do usuário
  const query = `
    SELECT IFNULL(SUM(amount), 0) AS saldo 
    FROM recargas 
    WHERE user_id = ?
      AND status = 'confirmado';
  `;

  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error("Erro ao buscar saldo:", err);
      return res.status(500).json({ error: "Erro ao buscar saldo" });
    }

    // Garante que o saldo seja sempre um número válido
    const saldo = parseFloat(results[0]?.saldo) || 0;
    res.json({ saldo });
  });
});

// Rota para pegar info do usuário logado (exibir referral_code, saldo etc.)
app.get("/me", (req, res) => {
  const authHeader = req.headers.authorization;
  if(!authHeader) return res.status(401).json({error: 'Token não fornecido'});
  
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    const userId = decoded.id;

    db.query("SELECT referral_code, saldo FROM users WHERE id = ?", [userId], (err, results) => {
      if (err) return res.status(500).json({error: "Erro ao buscar dados"});
      if (results.length === 0) return res.status(404).json({error: "Usuário não encontrado"});

      const { referral_code, saldo } = results[0];
      res.json({ referral_code, saldo });
    });
  } catch (error) {
    res.status(401).json({error: "Token inválido"});
  }
});

// Rota padrão para redirecionar para login
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Iniciar servidor
app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});
