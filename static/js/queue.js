
let refreshSchedule = -1;

function updateQueue() {
    if (refreshSchedule !== -1) {
        clearTimeout(refreshSchedule);
    }

    fetch("/api/queue")
        .then(resp => {
            if (resp.ok) {
                return resp.json();
            } else {
                throw Error("Error loading queue");
            }
        })
        .then(data => {
            setQueue(data);
        })
        .catch(() => {})
        .finally(() => {
            refreshSchedule = setTimeout(updateQueue, 5000);
        });
}

updateQueue();


function setQueue(data) {
    let queueDiv = document.getElementById("queue");
    while (queueDiv.firstChild) {
        queueDiv.firstChild.remove();
    }

    let generalHeader = document.createElement("h3");
    generalHeader.innerText = "Overall Queue Stats:";
    queueDiv.append(generalHeader)

    let generalContent = document.createElement("p");

    if (data.general.oldest_unfinished) {
        generalContent.append("Oldest unfinished job: " + new Date(data.general.oldest_unfinished).toString());
    } else {
        generalContent.innerText = "Queue is empty!";
    }
    queueDiv.append(generalContent);

    let decomps = Object.keys(data.per_decompiler).sort((a, b) => {
        let aName = data.per_decompiler[a].decompiler.name.toLowerCase();
        let bName = data.per_decompiler[b].decompiler.name.toLowerCase();
        if (aName < bName)
            return -1;
        if (aName > bName)
            return 1;
        return 0;
    });

    for (let id of decomps) {
        let decompQueue = data.per_decompiler[id];

        let decompHeader = document.createElement("h4");
        decompHeader.innerText = decompQueue.decompiler.name + " " + decompQueue.decompiler.version + (decompQueue.decompiler.revision === "" ? "" : " (") + decompQueue.decompiler.revision + (decompQueue.decompiler.revision === "" ? "" : ")") + ":";
        queueDiv.append(decompHeader)

        let decompContent = document.createElement("p");
        if (decompQueue.oldest_unfinished) {
            decompContent.append("Oldest unfinished job: " + new Date(decompQueue.oldest_unfinished).toString());
        } else {
            decompContent.innerText = "Queue is empty!";
        }
        queueDiv.append(decompContent);
    }
}
