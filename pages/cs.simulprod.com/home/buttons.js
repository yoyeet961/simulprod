document.addEventListener('DOMContentLoaded', () => {
  // Select all buttons on the page
  const buttons = document.querySelectorAll('button');

  // Add a click event listener to each button
  buttons.forEach(button => {
    button.addEventListener('click', () => {
      setTimeout(() => {

        // Select all elements with the class "results hidden"
        const hiddenElements = document.querySelectorAll('.hidden');

        // Loop through the hidden elements and remove the "hidden" class
        hiddenElements.forEach(element => {
          element.classList.remove('hidden');
        });
      }, 800);
    });
  });
});