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
    e = qa(".item");
    for (var i = 1; i < e.length; i++) {
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
    n.style.opacity = '0';
    n.style.height = '0';
    var ndata = [];
    for (var i = 0; i < titles.length; i++) {
        ndata.push(HTMLEncode(titles[i]))
    }
    n.innerHTML = '<input type="checkbox" class="select-vid"><div class="vid-container"><video-js oncontextmenu="return false" controls id="video' + id + '"><source src="' + url + '"></video-js></div><div class="item-opt"><div class="filename"></div><input class="input-filename" id="filename' + id + '" list="list' + id + '"><datalist id="list' + id + '"><option>' + ndata.join('</option><option>') + '</option></datalist><div class="fileext"></div><select class="select-fileext"><option>.mp4</option><option>.mkv</option><option>.m4v</option><option>.flv</option></select><button class="btn">Download</button>';
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
        n.style.height = ''
    }, 50);
}

function GetVideos(r = true) {
    fetch("/get-titles").then(response => response.json()).then(data => {
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
    fetch("/get-status").then(response => response.json(), () => { setTimeout(RefreshStatus, 300) }).then(data => {
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