async function scanURL() {

    const url = document.getElementById("url").value.trim();

    if (url === "") {
        alert("Enter URL");
        return;
    }

    const result = document.getElementById("result");

    result.innerHTML = "🔄 Scanning...";
    result.style.color = "#ffffff";

    try {

        const response = await fetch("/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        if (!response.ok) {
            throw new Error("Server error: " + response.status);
        }

        const data = await response.json();

        if (data.status === "Safe") {

            result.innerHTML =
                "✅ SAFE WEBSITE<br><br>" +
                "Confidence : " +
                data.confidence +
                "%";

            result.style.color = "limegreen";

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
            "Unable to connect to server.";

        result.style.color = "red";
    }
}


async function loadHistory() {

    try {

        // IMPORTANT:
        // Do NOT use 127.0.0.1:5000 on Render.
        // Use the same deployed backend.

        const response = await fetch("/history");

        if (!response.ok) {
            throw new Error("History server error");
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

        if (html === "") {
            html = "No History";
        }

        document.getElementById("history").innerHTML = html;

    } catch (error) {

        console.error("History Error:", error);

        document.getElementById("history").innerHTML =
            "Unable to load history.";

    }
}


// Load history when page opens
loadHistory();