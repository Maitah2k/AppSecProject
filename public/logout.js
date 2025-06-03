const server = `${window.location.origin}/logout`;

function logout()
{
    fetch(server, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.message == "success")
            window.location.href = 'index.html';
        else
            console.log(data.message);
    })
}

const logoutBtn = document.getElementById("logoutbtn");
logoutBtn.addEventListener("click", logout);