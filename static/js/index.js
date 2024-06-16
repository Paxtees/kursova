const mainDiv = document.querySelector('.main');
const lesgoButton = document.querySelector('.lesgo');

mainDiv.style.display = 'none';
lesgoButton.style.display = 'block';

lesgoButton.addEventListener('click', function() {
  mainDiv.style.display = 'block';
  // lesgoButton.style.display = 'none';
});

document.addEventListener('DOMContentLoaded', function () {
    var closeButton = document.querySelector('.close');
    var mainElement = document.querySelector('.main');

    closeButton.addEventListener('click', function () {
        mainElement.style.display = 'none';
        lesgoButton.style.display = 'block';
    });
});

