function checkuser($) {
    var index = layer.load();
    var url = "/ashx/LoginServer.ashx";
    var pm = {
        action: "checkuser",
        time: Math.random()
    };
    $.ajaxSettings.async = false;
    $.getJSON(url, pm,
        function (json) {
            if (json.State == "200") {
                if (json.JsonResult == "已登录") {
                    location.href = "/center/user.html";
                }
            }
            layer.close(index);
        });
}

function CommAlert(json) {
    if (json.State == "300") {
        layer.msg(json.JsonResult, {
            shade: [0.8, '#393D49'],
            shadeClose: true,
            time: 2000
        });
    }
    if (json.State == "500") {
        window.location.href = '/login.html'
    }
}

function error(msg) {
    layer.msg(msg, {
        shade: [0.8, '#393D49'],
        shadeClose: true,
        time: 2000
    });
}

function success(msg) {
    layer.msg(msg, {
        shade: [0.8, '#393D49'],
        shadeClose: true,
        time: 2000,
        skin: 'demo'
    });
}

function getUrlParam1(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
    var r = decodeURI(window.location.search.substr(1)).match(reg);
    if (r != null) return unescape(r[2]); return "";
}

function getUrlParam(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
    var r = decodeURI(window.location.search.substr(1)).match(reg);
    if (r != null) return unescape(r[2]); return null;
}
