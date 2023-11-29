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
        editor.setHighlightActiveLine(true);
        editor.setHighlightGutterLine(true);
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
        try {
            if (check.checked) {
                umami.track("Show decompiler " + info.name);
            } else {
                umami.track("Hide decompiler " + info.name);
            }
        } catch (e) {

        }
    });
});

document.querySelector("#binary_upload_form input[name='file']").required = true;

let numDecompilers = Object.keys(decompilerFrames).length;
let resultUrl;

// For keeping track of line change events-- they will also trigger when we update the contents
// of the textbox, so we need to ignore those.
let loading = {};

function logError(err_title, err_msg, do_alert=false) {
    console.error(err_title, err_msg);
    if (do_alert) {
        alert(err_title);
    }
}

function clearOutput(decompiler_name) {
    updateTextEdit(decompiler_name, "");
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

function clearFrameInputs() {
    Object.keys(decompilerFrames).forEach(i => updateTextEdit(i, ""));
    Object.values(decompilerRerunButtons).forEach(i => i.hidden = true);
}

function updateTextEdit(decompiler_name, contents) {
    loading[decompiler_name] = true;
    decompilerFrames[decompiler_name].session.getDocument().setValue(contents);
    decompilerFrames[decompiler_name].resize();
    loading[decompiler_name] = false;
}


function displayResult(resultData, is_sample) {
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
    decompilerVersions[decompiler_name].setAttribute("title", `${decompiler_name} version ${decompiler_version}\nAnalysed ${created}\nAnalysis took ${analysis_time.toFixed(2)} seconds`);

    if (resultData['error'] !== null) {
        updateTextEdit(decompiler_name, `Error decompiling: ${resultData['error']}`);
        rerun_button.hidden = is_sample;
        return;
    }

    fetch(url)
    .then(resp => resp.text())
    .then(data => {
        updateTextEdit(decompiler_name, data);
        loading[decompiler_name] = true;
        let lineNumbers = new URLSearchParams(window.location.hash.substring(1));
        let row = lineNumbers.get(decompiler_name);
        if (row !== null) {
            frame.gotoLine(parseInt(row));
        }
        rerun_button.hidden = is_sample;
        loading[decompiler_name] = false;
    })
    .catch(err => {
        logError("Error retrieving result", err);
        updateTextEdit(decompiler_name, "// Error retrieving result: " + err);
    })
}

let refreshSchedule = -1;
let timerSchedule = -1;

function compareVersions(thisVersionStr, otherVersionStr) {
    // Compare versions and, if otherer, overwrite
    let thisVersion = thisVersionStr.split(".").flatMap(version => version.split('-'));
    let otherVersion = otherVersionStr.split(".").flatMap(version => version.split('-'));
    for (let i = 0; i < Math.min(thisVersion.length, otherVersion.length); i++) {
        let thisVi = parseInt(thisVersion[i]);
        let otherVi = parseInt(otherVersion[i]);
        if (!isNaN(thisVi) && !isNaN(otherVi)) {
            if (parseInt(thisVersion[i]) < parseInt(otherVersion[i]))
                return true;
            if (parseInt(thisVersion[i]) > parseInt(otherVersion[i]))
                return false;
        } else {
            if (thisVersion[i] < otherVersion[i])
                return true;
            if (thisVersion[i] > otherVersion[i])
                return false;
        }
    }
    if (thisVersion.length < otherVersion.length)
        return true;
    if (thisVersion.length > otherVersion.length)
        return false;
    return false;
}

function loadResults(is_sample) {
    let finishedResults = [];
    let startTime = Date.now();

    let timerUpdate = () => {
        if (timerSchedule !== -1) {
            clearTimeout(timerSchedule);
        }

        for (let decompilerName of Object.keys(decompilers)) {
            if (finishedResults.indexOf(decompilerName) === -1) {
                let elapsedSecs = ((Date.now() - startTime) / 1000).toFixed(0);
                updateTextEdit(decompilerName, "// Waiting for data... (" + elapsedSecs + "s)");
            }
        }
        if (finishedResults.length < numDecompilers) {
            timerSchedule = setTimeout(timerUpdate, 1000);
        }
    };
    let refresh = () => {
        if (refreshSchedule !== -1) {
            clearTimeout(refreshSchedule);
        }

        fetch(resultUrl)
            .then(resp => {
                if (resp.ok) {
                    return resp.json();
                } else {
                    throw Error("Error fetching results");
                }
            })
            .then(data => {
                let bestVersions = {};
                for (let i of data['results']) {
                    if (!Object.keys(bestVersions).includes(i['decompiler']['name'])) {
                        bestVersions[i['decompiler']['name']] = i;
                        continue;
                    }

                    let oldBest = bestVersions[i['decompiler']['name']];
                    let oldVersion = oldBest['decompiler']['version'];
                    let newVersion = i['decompiler']['version'];

                    if (compareVersions(oldVersion, newVersion)) {
                        bestVersions[i['decompiler']['name']] = i;
                    }
                }

                for (let i of Object.values(bestVersions)) {
                    if (i['decompiler'] === null)
                        continue;
                    let decompilerName = i['decompiler']['name'];
                    if (!finishedResults.includes(decompilerName)) {
                        displayResult(i, is_sample);
                        finishedResults.push(decompilerName);
                    }
                }
            })
            .catch((e) => {
                console.error(e);
            })
            .finally(() => {
                if (finishedResults.length < numDecompilers) {
                    refreshSchedule = setTimeout(refresh, 5000);
                }
            })
    };

    refresh();
    timerUpdate();
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
        addHistoryEntry(data['id']);
        loadAllDecompilers(data['id'], false);
    })
    .catch(err => {
        logError(err, err, true);
    });
}

function loadAllDecompilers(binary_id, is_sample) {
    resultUrl = `${location.origin}${location.pathname}api/binaries/${binary_id}/decompilations/`;
    loadResults(is_sample);
}

function addHistoryEntry(binary_id) {
    const url = new URL(window.location);
    url.searchParams.set('id', binary_id);
    window.history.pushState({}, '', url);
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
        loadResults(false);
    })
    .catch(err => {
        logError(err, err, true);
    });
    try {
        umami.track("Rerun decompiler " + decompiler_name);
    } catch (e) {

    }
}


document.getElementById('file').addEventListener('change', (e) => {
    e.preventDefault();
    clearFrameInputs();
    uploadBinary();
});
document.getElementById('samples').addEventListener('change', (e) => {
    let id = document.getElementById('samples').value;
    if (id != '') {
        e.preventDefault();
        clearFrameInputs();
        addHistoryEntry(id);
        loadAllDecompilers(id, true);
    }
});

for (const decompiler of Object.keys(decompilerFrames)) {
    decompilerFrames[decompiler].session.selection.on("changeCursor", function(e, selection) {
        if (loading[decompiler])
            return;
        const row = selection.getCursor()['row'] + 1;
        let lineNumbers = new URLSearchParams(window.location.hash.substring(1));
        lineNumbers.set(decompiler, row);
        window.location.hash = lineNumbers.toString();
    });
}

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
    let wasSample = false;
    let sampleSelect = document.getElementById('samples');
    for (let i = 0; i < sampleSelect.childElementCount; i ++) {
        if (sampleSelect.children[i].value === id) {
            sampleSelect.value = id;
            wasSample = true;
            break;
        }
    }

    if (!wasSample) {
        sampleSelect.value = "";
    }

    loadAllDecompilers(id, wasSample);
}

setTimeout(() => {
    if (document.getElementById("banner") !== null) {
        try {
            umami.track("Shown queue banner");
        } catch (e) {

        }
    }
}, 1000);
