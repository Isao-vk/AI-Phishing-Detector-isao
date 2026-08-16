async function scanURL() {

    const url = document.getElementById("url").value;

    if (url == "") {
        alert("Enter URL");
        return;
    }

    const response = await fetch("http://127.0.0.1:5000/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: url
        })
    });

    const data = await response.json();

    const result = document.getElementById("result");

    if (data.status == "Safe") {

        result.innerHTML =
            "✅ SAFE WEBSITE <br><br> Confidence : "
            + data.confidence + "%";

        result.style.color = "green";

    } else {

        result.innerHTML =
            "❌ PHISHING WEBSITE <br><br> Confidence : "
            + data.confidence + "%";

        result.style.color = "red";
    }

    // Refresh history after scan
    loadHistory();
}


async function loadHistory() {

    const response = await fetch("http://127.0.0.1:5000/history");

    const history = await response.json();

    let html = "";

    history.forEach(item => {

        html += `
        <div style="border:1px solid #ddd;padding:10px;margin:10px;border-radius:8px;text-align:left;">
            <b>URL :</b> ${item.url}<br>
            <b>Status :</b> ${item.status}<br>
            <b>Confidence :</b> ${item.confidence}%<br>
            <b>Time :</b> ${item.time}
        </div>
        `;

    });

    if (html == "") {
        html = "No History";
    }

    document.getElementById("history").innerHTML = html;

}

// Load history automatically
loadHistory();