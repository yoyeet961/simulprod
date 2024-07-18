document.addEventListener('click', function(event) {
  if (event.target.tagName === 'BUTTON') {
    const hiddenElements = document.querySelectorAll('.hidden');
    const hidden2Elements = document.querySelectorAll('.hidden2');

    hiddenElements.forEach(element => {
      element.classList.remove('hidden');
    });

    setTimeout(() => {
      hiddenElements.forEach(element => {
        element.classList.add('hidden');
      });

      hidden2Elements.forEach(element => {
        element.classList.remove('hidden2');
      });
    }, 800);
  }
});