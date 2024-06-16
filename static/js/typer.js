var message = "Привет, чтобы продолжить вам необходимо пройти";
var message2 = "регистрацию или авторизацию";
var speed = 17;

var i = 0;
var g = 0;




function autoTyper(){
    document.getElementById("text").innerHTML += message.charAt(i);
    i++;
    if(i === message.length){
        autoTyper2();
    }
    setTimeout(autoTyper, speed);
}

function autoTyper2(){
    document.getElementById("text2").innerHTML += message2.charAt(g);
    g++;

    setTimeout(autoTyper2, speed);
}


autoTyper();
