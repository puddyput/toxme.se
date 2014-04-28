function SC_performSearch() {
    var query = document.getElementById("search_text").value.trim();
    if (query === "")
        return;
    window.searchIsRunning = 1
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        SC_lookupStatusDidChange(xhr);
    }
    xhr.open("POST", "/api", true);
    xhr.send(JSON.stringify({
        "a": 3,
        "name": query,
    }));
    SC_showFailureOnUI("Please wait...")
    console.log(query);
}

function SC_showFailureOnUI(s) {
    document.getElementById("lookup_results").style.display = "none";
    var message = document.getElementById("lookup_error");
    message.style.display = "block";
    message.textContent = s;
}

function SC_errorStringFromCode(ec) {
    switch (ec) {
        case -41:
            return "Lookup failed: unspecified error.";
        case -42:
            return "Lookup failed: user not found.";
        case -43:
            return "Lookup failed: internal error! Please report it on GitHub."
        case -3:
            return "Lookup failed: the address wasn't valid."
    }
}

function SC_showResultOnUI(payload) {
    document.getElementById("lookup_error").style.display = "none";
    var message = document.getElementById("lookup_results");
    message.style.display = "block";
    document.getElementById("lu_oname").textContent = payload.name;
    document.getElementById("lu_regdomain").textContent = payload.regdomain;
    var source;
    if (payload.source == 1) {
        source = "local user";
    } else {
        source = "remote user";
    }
    document.getElementById("lu_stype").textContent = source;
    document.getElementById("lu_rectype").textContent = payload.version;
    if (payload.public_key.length == 64) {
        document.getElementById("results").className = "v2"
        document.getElementById("lu_user_pk").textContent = payload.public_key;
    } else {
        document.getElementById("results").className = "v1"
        document.getElementById("lu_user_id").textContent = payload.public_key;
    }
    var sigbox = document.getElementById("lu_user_sig");
    sigbox.textContent = payload.verify.detail;
    sigbox.className = payload.verify.status == 1 ? "good"
                       : (payload.verify.status == 2 ? "bad" : "undecided")
}

function SC_lookupStatusDidChange(sender) {
    if (sender.readyState == 4) {
        var respload;
        try {
            respload = JSON.parse(sender.responseText);
        } catch (e) {
            respload = null;
        }
        
        if (sender.status != 200) {
            var ec = 0;
            if (respload && (ec = parseInt(respload.c))) {
                SC_showFailureOnUI(SC_errorStringFromCode(ec));
            } else {
                SC_showFailureOnUI("Lookup failed: server responded \
                                    with status code " + sender.status);
            }
            return;
        }
            
        console.log(respload);
        SC_showResultOnUI(respload);
    }
}

function SC_init() {
    document.getElementById("search_go").addEventListener(
        "click", SC_performSearch, 1
    );
}