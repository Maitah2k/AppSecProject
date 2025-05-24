const server = "http://localhost:6960/register.html";

function registerUser()
{
    const usr_input = document.getElementById("username").value;
    const email_input = document.getElementById("email").value;
    const passwd_input = document.getElementById("password").value;

    console.log(usr_input, passwd_input);

    const statusmsg = document.getElementById("statusmsg");

    fetch(server, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            usr: usr_input,
            email: email_input,
            password: passwd_input
        })
    })
    .then(response => response.json())
    .then(data => {
        statusmsg.innerText = data.message;
        statusmsg.style.display = "block";
        if (data.message == "success")
            statusmsg.style.color = "green";
        
        else
            statusmsg.style.color = "red";
    })
    .catch(error => {
        statusmsg.innerText = error;
        statusmsg.style.display = "block";
        statusmsg.style.color = "red";
        console.error('Error:', error);
    });
}

const registerbtn = document.getElementById("registerbtn");
registerbtn.addEventListener("click", registerUser);