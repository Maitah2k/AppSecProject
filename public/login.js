const server = `${window.location.origin}/login.html`;

function loginUser()
{
    const usr_input = document.getElementById("username").value;
    const passwd_input = document.getElementById("password").value;

    const statusmsg = document.getElementById("statusmsg");

    fetch(server, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            usr: usr_input,
            password: passwd_input
        })
    })
    .then(response => response.json())
    .then(data => {
        
        if (data.message == "success")
        {    
            console.log(data.redirect);
            window.location.href = data.redirect;
        }
            
        else if (data.message == "fail")
            statusmsg.innerText = "Incorrect username or password";
        
        else
            statusmsg.innerText = data.message;

        statusmsg.style.display = "block";
        statusmsg.style.color = "red";
    })
    .catch(error => {
        statusmsg.innerText = error;
        statusmsg.style.display = "block";
        statusmsg.style.color = "red";
        console.error('Error:', error);
    });
}

const loginbtn = document.getElementById("loginbtn");
loginbtn.addEventListener("click", loginUser);