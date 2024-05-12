var form = document.querySelector('form');
var acceptButton = form.querySelector('button[name="accept_btn"]');
var declineButton = form.querySelector('button[name="decline_btn"]');

var status_info = ""

acceptButton.addEventListener('click', function(event) {
    status_info = "accepted";
});

declineButton.addEventListener('click', function(event) {
    status_info = "declined";
});

function submitForm(event){
    event.preventDefault();

    const form = event.target; // getting the form

    let user = document.getElementById("user"); // getting the values of symetric key and username
    let username = user.dataset.value;
    let enc_symKey = user.dataset.publickey;
    let symKey = decrypt(enc_symKey,username) // decrypting the symmetric key

    const status_input = document.createElement('input');
    status_input.type = 'hidden';
    status_input.name = 'status_info';
    status_input.value = status_info;

    if (status_info == "accepted"){ // if "old" device accepted to give access
        const privateKey = document.createElement('input');
        const salt_user = document.createElement('input');
    
        let private_key = localStorage.getItem(username+"PrKey");
        let salt = localStorage.getItem(username+"_salt");

        let encrypted_private_key = CryptoJS.AES.encrypt(private_key, symKey); // encrypting the private key
        privateKey.type = 'hidden';
        privateKey.name = 'private_key';
        privateKey.value = encrypted_private_key;
        salt_user.type = 'hidden';
        salt_user.name = 'salt_user';
        salt_user.value = salt;
        form.appendChild(privateKey); // encrypted private key and salt will be sent
        form.appendChild(salt_user);
    }
    form.appendChild(status_input);

    return form.submit();
}