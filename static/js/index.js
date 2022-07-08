ace.config.set('basePath', 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.14/');

let decompilerContainers = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_container"))
    .map(i => [i.id.replace(/(^container_)/, ''), i])
);

let decompilerFrames = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_output"))
    .map(i => {
        let id = i.id;
        let editor = ace.edit(id);
        editor.setReadOnly(true);
        editor.session.setMode("ace/mode/c_cpp");
        return [id, editor];
    })
);

let decompilerTitles = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_title"))
    .map(i => [i.id.replace(/(^title_)/, ''), i])
);

let decompilerVersions = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_version"))
    .map(i => [i.id.replace(/(^version_)/, ''), i])
);

let decompilerRerunButtons = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_rerun"))
    .map(i => [i.id.replace(/(^rerun_)/, ''), i])
);

let decompilerSelectChecks = Object.fromEntries(
    Object.values(document.getElementsByClassName("decompiler_select"))
    .map(i => [i.id.replace(/(^select_)/, ''), i])
);

let decompilerResultUrls = {};

let decompilers = JSON.parse(document.getElementById("decompilers_json").textContent);

Object.keys(decompilerSelectChecks).forEach((decompiler) => {
    let check = decompilerSelectChecks[decompiler];
    let info = decompilers[decompiler];
    check.checked = info.featured;
    check.addEventListener('change', () => {
        info.featured = check.checked;
        updateFrames();
    });
});

document.querySelector("#binary_upload_form input[name='file']").required = true;

let numDecompilers = Object.keys(decompilerFrames).length;
let resultUrl;

function logError(err_title, err_msg, do_alert=false) {
    console.error(err_title, err_msg);
    if (do_alert) {
        alert(err_title);
    }
}

function clearOutput(decompiler_name) {
    decompilerFrames[decompiler_name].session.getDocument().setValue("");
    decompilerRerunButtons[decompiler_name].hidden = true;
    delete decompilerResultUrls[decompiler_name];
}

function updateFrames() {
    let hasPrevious = false;
    Object.keys(decompilerContainers).forEach((decompiler) => {
        let info = decompilers[decompiler];

        if (hasPrevious) {
            decompilerContainers[decompiler].classList.add('with_line');
        } else {
            decompilerContainers[decompiler].classList.remove('with_line');
        }

        if (info.featured) {
            decompilerContainers[decompiler].classList.remove('hidden');
            hasPrevious = true;
        } else {
            decompilerContainers[decompiler].classList.add('hidden');
        }
    });
}

function displayResult(resultData) {
    // If a new decompiler comes online before we refresh, it won't be in the list
    if (Object.keys(decompilers).indexOf(resultData['decompiler']['name']) === -1)
        return;
    let url = resultData['download_url'];
    let analysis_time = resultData['analysis_time'];
    let created = new Date(resultData['created']);
    let decompiler_name = resultData['decompiler']['name'];
    let decompiler_version = resultData['decompiler']['version'];
    let decompiler_revision = resultData['decompiler']['revision'];
    let frame = decompilerFrames[decompiler_name];
    let rerun_button = decompilerRerunButtons[decompiler_name];
    decompilerResultUrls[decompiler_name] = resultData['url'];
    decompilerTitles[decompiler_name].innerText = `${decompiler_name}`;
    if (decompiler_revision !== '') {
        if (decompiler_revision.length > 8) {
            decompiler_revision = decompiler_revision.substring(0, 8);
        }
        decompilerVersions[decompiler_name].innerText = `${decompiler_version} (${decompiler_revision})`;
    } else {
        decompilerVersions[decompiler_name].innerText = `${decompiler_version}`;
    }

    if (resultData['error'] !== null) {
        frame.session.getDocument().setValue(`Error decompiling: ${resultData['error']}`);
        rerun_button.hidden = false;
        return;
    }

    fetch(url)
    .then(resp => resp.text())
    .then(data => {
        frame.session.getDocument().setValue(data);
        frame.resize();
        rerun_button.hidden = false;
    })
    .catch(err => {
        logError("Error retrieving result", err);
        frame.session.getDocument().setValue("// Error retrieving result: " + err);
    })
}


function getResult(decompiler_name) {
    let finishedResults = [];
    decompilerFrames[decompiler_name].session.getDocument().setValue("// Waiting for data...");
    decompilerRerunButtons[decompiler_name].hidden = true;

    let startTime = Date.now();

    let resultInterval = setInterval(() => {
        fetch(resultUrl)
        .then(resp => {
            if (resp.ok) {
                return resp.json();
            }
            else {
                throw Error("Error fetching results");
            }
        })
        .then(data => {
            for (let i of data['results']) {
                if (i['decompiler'] === null)
                    continue;
                let decompilerName = i['decompiler']['name'];
                if (!finishedResults.includes(decompilerName)) {
                    displayResult(i);
                    finishedResults.push(decompilerName);
                }
                if (finishedResults.length === numDecompilers) {
                    clearInterval(resultInterval);
                }
            }
            if (finishedResults.indexOf(decompiler_name) === -1) {
                let elapsedSecs = ((Date.now() - startTime) / 1000).toFixed(0);
                decompilerFrames[decompiler_name].session.getDocument().setValue("// Waiting for data... (" + elapsedSecs + "s)");
            }
        })
    }, 1000);
}


function uploadBinary() {
    resultUrl = undefined;
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    let uploadForm = document.getElementById('binary_upload_form');
    if (!uploadForm.checkValidity()) {
        uploadForm.reportValidity();
        return;
    }
    let formData = new FormData(uploadForm);

    fetch('/api/binaries/', {
        method: 'POST',
        body: formData,
        headers: {'X-CSRFToken': csrfToken},
        mode: 'same-origin'
    })
    .then(async(resp) => {
        if (resp.ok) {
            return resp.json();
        }
        else {
            if (resp.status == 413) {
                throw Error("File too large");
            }
            if (resp.status == 429) {
                throw Error((await resp.json())['detail']);
            }
            else {
                throw Error("Error uploading binary");
            }
        }
    })
    .then(data => {
        const url = new URL(window.location);
        url.searchParams.set('id', data['id']);
        window.history.pushState({}, '', url);
        resultUrl = data["decompilations_url"];
        for (const decompiler_name of Object.keys(decompilerFrames)) {
            getResult(decompiler_name);
        }
    })
    .catch(err => {
        logError(err, err, true);
    });
}


function rerunDecompiler(decompiler_name) {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    fetch(decompilerResultUrls[decompiler_name] + 'rerun/', {
        method: 'POST',
        headers: {'X-CSRFToken': csrfToken},
        mode: 'same-origin'
    })
    .then(resp => {
        if (!resp.ok) {
            throw Error("Error rerunning binary");
        }
    })
    .then(() => {
        clearOutput(decompiler_name);
        getResult(decompiler_name);
    })
    .catch(err => {
        logError(err, err, true);
    });
}


document.getElementById('upload_binary').addEventListener('click', (e) => {
    e.preventDefault();
    Object.values(decompilerFrames).forEach(i => i.session.getDocument().setValue(""));
    Object.values(decompilerRerunButtons).forEach(i => i.hidden = true);
    uploadBinary();
});

Object.entries(decompilerRerunButtons)
    .forEach(([name, elem]) => {
        elem.addEventListener('click', (e) => {
            e.preventDefault();
            rerunDecompiler(name);
        })
    });
updateFrames();

let params = new URL(location).searchParams;
let id = params.get("id");
if (id !== null) {
    resultUrl = `${location.origin}${location.pathname}api/binaries/${id}/decompilations/`;
    for (const decompiler_name of Object.keys(decompilerFrames)) {
        getResult(decompiler_name);
    }
}
