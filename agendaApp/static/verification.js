function getCookie(name) { // this function will be used to get the CSRF token
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
}

function verifyOTP(){

    // verify the otp
    let enc_otp = document.getElementById('otp');
    let value = enc_otp.dataset.value;
    let username = enc_otp.dataset.username;

    var otp = decrypt(value,username); // otp will be decrypted using the user's private key

    fetch('/verification/', {
        method: 'POST',
        body: JSON.stringify({
        message: otp // send the decrypted OTP value to the server
        }),
        headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')
        }
    });

}

verifyOTP();

setTimeout(function() {
  location.reload();
}, 1000); // reload the view to see which action the server will take (if he received the otp and grant access or not) 
