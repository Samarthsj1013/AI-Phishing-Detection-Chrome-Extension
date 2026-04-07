document.getElementById("scanBtn").addEventListener("click", () => {

  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    const url = tabs[0].url;

    fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {

      document.getElementById("result").innerText = "Result: " + data.result;
      document.getElementById("confidence").innerText = "Confidence: " + data.confidence + "%";

      let reasonsList = document.getElementById("reasons");
      reasonsList.innerHTML = "";

      data.reasons.forEach(reason => {
        let li = document.createElement("li");
        li.innerText = reason;
        reasonsList.appendChild(li);
      });

    })
    .catch(err => {
      console.error(err);
      document.getElementById("result").innerText = "Error connecting to server";
    });

  });

});