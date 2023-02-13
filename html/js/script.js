function qa(c) {
    return document.querySelectorAll(c);
}

function q(c) {
    return document.querySelector(c);
}

function OpenDownList() {
    q(".downlist-cover").style.display = "block";
    setTimeout(() => {
        q(".downlist-cover").style.opacity = 1;
        q(".downlist-window").style.top = "15%"
    }, 50)
}

function CloseDownList() {
    q(".downlist-cover").style.opacity = 0;
    q(".downlist-window").style.top = "calc(15% + 2rem)";
    setTimeout(() => {
        q(".downlist-cover").style.display = "none";
    }, 500)
}

function RequireScan() {
    fetch("/scan");
}

function HTMLEncode(html) {
    var temp = document.createElement("div");
    (temp.textContent != null) ? (temp.textContent = html) : (temp.innerText = html);
    var output = temp.innerHTML;
    temp = null;
    return output;
}

var count = 0,
    shown_videos = {};

function ClearVideos() {
    shown_videos = {};
    down_status = 0;
    e = qa(".item");
    for (var i = 1; i < e.length; i++) {
        e[i].remove()
    }
    e = qa("#down-list>.list-item")
    for (var i = 0; i < e.length; i++) {
        e[i].remove()
    }
}

function AddVideo(url, titles) {
    if (shown_videos[url] != undefined) {
        for (var i = 0; i < titles.length; i++) {
            if (!shown_videos[url]["titles"].includes(titles[i])) {
                q("#list" + shown_videos[url]["id"]).innerHTML += "<option>" + HTMLEncode(titles[i]) + "</option>";
                shown_videos[url]["titles"].push(titles[i])
            }
        }
        return
    }
    id = ++count;
    var n = document.createElement("div");
    n.setAttribute("class", "item");
    n.setAttribute("id", "item" + id);
    n.setAttribute("down-url", url);
    n.style.opacity = '0';
    var ndata = [];
    for (var i = 0; i < titles.length; i++) {
        ndata.push(HTMLEncode(titles[i]))
    }
    n.innerHTML = '<input type="checkbox" class="select-vid"><div class="vid-container"><video-js oncontextmenu="return false" controls id="video' + id + '"><source src="' + url + '"></video-js></div><div class="item-opt"><div class="filename"></div><input class="input-filename" id="filename' + id + '" list="list' + id + '"><datalist id="list' + id + '"><option>' + ndata.join('</option><option>') + '</option></datalist><div class="fileext"></div><select class="select-fileext" id="ext' + i + '"><option>.mp4</option><option>.mkv</option><option>.m4v</option><option>.flv</option></select><button class="btn" onclick="Download(' + i + ')">Download</button>';
    q(".content").appendChild(n);
    for (var i = 0; i < ndata.length; i++) {
        if ((!ndata[i].toLowerCase().includes("classin")) && (!ndata[i].toLowerCase().includes("classroom"))) {
            q("#filename" + id).value = ndata[i];
            break;
        }
    }
    shown_videos[url] = { "titles": titles, "id": id };
    videojs("video" + id);
    setTimeout(() => {
        n.style.opacity = '1';
    }, 50);
}

function GetVideos(r = true) {
    fetch("/get-titles").then(response => response.json(), () => { location.href = "about:blank" }).then(data => {
        for (var url in data) {
            AddVideo(url, data[url])
        }
        if (r) {
            setTimeout(GetVideos, 1000);
        }
    });
}
GetVideos();

var modifying = false,
    modify_timeout = 0,
    modify_focus = false;

function StartModify() {
    modifying = true;
    clearTimeout(modify_timeout);
    q(".delay-int").style.boxShadow = "0 0 2px 2px #e04";
    modify_timeout = setTimeout(StopModify, 10000);
}

function StopModify() {
    ChangeDelayTime();
    modifying = false;
    clearTimeout(modify_timeout);
    q(".delay-int").style.boxShadow = "";
}

function RefreshStatus() {
    fetch("/get-status").then(response => response.json(), () => { location.href = "about:blank" }).then(data => {
        q(".conf-panel>.check-big").checked = data["autoscan"];
        if (!modifying) { q(".delay-int").value = data["wait_interval"] }
        setTimeout(RefreshStatus, 1000)
    })
}
RefreshStatus()

function SwitchAutoScan() {
    fetch(q(".conf-panel>.check-big").checked ? "/enable-autoscan" : "/disable-autoscan")
}

function ChangeDelayTime() {
    fetch("/set-autoscan-delay", { method: 'POST', body: q(".delay-int").value.toString() });
}

var down_status = 0;

function RefreshDownloads() {
    fetch("/download-status").then(response => response.json(), () => { location.href = "about:blank" }).then(data => {
        if (data.length > down_status) {
            for (var i = down_status; i < data.length; i++) {
                var n = document.createElement("div");
                n.setAttribute("id", "down-item" + i);
                n.setAttribute("class", "list-item");
                n.innerHTML = '<div class="down-filename">' + HTMLEncode(data[i]["name"]) + '</div><div class="down-filepath">' + HTMLEncode(data[i]["path"]) + '</div><div class="percentage">' + data[i]["percent"].toFixed(2) + '%</div><div class="progress-bar-container"><div class="progress-bar"></div></div><div class="cancel-btn" id="cancel-btn' + i + '">×</div><div class="error-message">' + HTMLEncode(data[i]["msg"]) + '</div>';
                q("#down-list").appendChild(n);
                q("#down-item" + i + ">.cancel-btn").onclick = Function('fetch("/cancel-download/' + i + '",{method:"DELETE"})');
                down_status++;
            }
        }
        var count = 0;
        for (var i = 0; i < data.length; i++) {
            var fn = q("#down-item" + i + ">.down-filename"),
                fp = q("#down-item" + i + ">.down-filepath"),
                fpc = q("#down-item" + i + ">.percentage"),
                fm = q("#down-item" + i + ">.error-message"),
                fpb = q("#down-item" + i + " .progress-bar"),
                fc = q("#cancel-btn" + i);
            var en_name = HTMLEncode(data[i]["name"]),
                en_path = HTMLEncode(data[i]["path"]),
                en_msg = HTMLEncode(data[i]["msg"]);
            if (fn.innerHTML !== en_name) { fn.innerHTML = en_name }
            if (fp.innerHTML !== en_path) { fp.innerHTML = en_path }
            if (fpc.innerHTML !== data[i]["percent"].toFixed(2) + "%") { fpc.innerHTML = data[i]["percent"].toFixed(2) + "%" }
            if (fm.innerHTML !== en_msg) { fm.innerHTML = en_msg }
            fpb.style.width = data[i]["percent"].toFixed(2) + "%";
            count += (data[i]["status"] == 5 || data[i]["status"] == 1) ? 1 : 0;
            if (data[i]["status"] == 1) {
                if (!fpb.classList.contains("progress-bar-downloading")) {
                    fpb.setAttribute("class", "progress-bar progress-bar-downloading")
                }
            } else
            if (data[i]["status"] == 4) {
                if (!fpb.classList.contains("progress-bar-success")) {
                    fpb.setAttribute("class", "progress-bar progress-bar-success")
                }
                fc.setAttribute("class", "cancel-btn-disabled");
                fc.onclick = null;
            } else if (data[i]["status"] == 2 || data[i]["status"] == 3) {
                if (!fpb.classList.contains("progress-bar-failed")) {
                    fpb.setAttribute("class", "progress-bar progress-bar-failed")
                }
                fc.setAttribute("class", "cancel-btn-disabled");
                fc.onclick = null;
            }
        }
        if (q(".notify-num").innerHTML != count) { q(".notify-num").innerHTML = count }
        setTimeout(RefreshDownloads, 500);
    })
}
RefreshDownloads();

function Download(index) {
    fetch("/require-download", { method: "POST", body: JSON.stringify({ "path": q("#path").value, "downloads": [{ "url": q("#item" + index).getAttribute("down-url"), "name": q("#filename" + index).value + q("#ext" + index).value }] }) });
}

function Download_Select() {
    var sel = qa(".item>.select-vid:checked");
    for (var i = 0; i < sel.length; i++) {
        Download(parseInt(sel[i].parentNode.getAttribute("id").slice(4)));
    }
}