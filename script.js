const BACKEND_URL = "https://ai-phishing-detector-isao.onrender.com";


async function scanURL() {

    const url = document.getElementById("url").value.trim();

    if (!url) {
        alert("Enter URL");
        return;
    }

    const result = document.getElementById("result");

    result.innerHTML = "🔄 Scanning...";
    result.style.color = "#ffffff";

    try {

        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        if (!response.ok) {
            throw new Error("Backend request failed");
        }

        const data = await response.json();

        if (data.status === "Safe") {

            result.innerHTML =
                "✅ SAFE WEBSITE<br><br>" +
                "Confidence : " +
                data.confidence +
                "%";

            result.style.color = "green";

        } else {

            result.innerHTML =
                "❌ PHISHING WEBSITE<br><br>" +
                "Confidence : " +
                data.confidence +
                "%";

            result.style.color = "red";
        }

        loadHistory();

    } catch (error) {

        console.error(error);

        result.innerHTML =
            "❌ BACKEND ERROR<br><br>" +
            "Unable to connect to phishing detection server.";

        result.style.color = "red";
    }
}


async function loadHistory() {

    const historyBox = document.getElementById("history");

    try {

        const response = await fetch(`${BACKEND_URL}/history`);

        if (!response.ok) {
            throw new Error("History request failed");
        }

        const history = await response.json();

        let html = "";

        history.forEach(item => {

            html += `
                <div style="
                    border:1px solid #ddd;
                    padding:10px;
                    margin:10px;
                    border-radius:8px;
                    text-align:left;
                ">

                    <b>URL :</b> ${item.url}<br>

                    <b>Status :</b> ${item.status}<br>

                    <b>Confidence :</b> ${item.confidence}%<br>

                    <b>Time :</b> ${item.time}

                </div>
            `;

        });

        historyBox.innerHTML =
            html || "No History";

    } catch (error) {

        console.error(error);

        historyBox.innerHTML =
            "Unable to load history.";

    }
}


loadHistory();