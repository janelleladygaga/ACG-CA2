const uploadForm = document.getElementById("uploadForm");
const fileInput = document.getElementById("fileInput");
const uploadStatus = document.getElementById("uploadStatus");
const fileList = document.getElementById("fileList");
const refreshBtn = document.getElementById("refreshBtn");

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  const response = await fetch("/upload", {
    method: "POST",
    body: formData,
  });
  const result = await response.json();

  uploadStatus.textContent = response.ok
    ? result.message
    : `Error: ${result.error}`;

  loadFileList();
});

async function loadFileList() {
  const response = await fetch("/files");
  const result = await response.json();

  fileList.innerHTML = "";
  for (const name of result.files) {
    const li = document.createElement("li");
    const link = document.createElement("a");
    link.href = `/download/${encodeURIComponent(name)}`;
    link.textContent = name;
    li.appendChild(link);
    fileList.appendChild(li);
  }
}

refreshBtn.addEventListener("click", loadFileList);
loadFileList();
