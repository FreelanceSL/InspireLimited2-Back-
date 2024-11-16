// Select input fields and button
const inputs = document.querySelectorAll("input");
const button = document.querySelector("button");
const resendButton = document.getElementById("resend-btn");

// Enable/disable inputs and manage transitions
inputs.forEach((input, index1) => {
  input.addEventListener("keyup", (e) => {
    const currentInput = input,
      nextInput = input.nextElementSibling,
      prevInput = input.previousElementSibling;

    // Clear input if it contains more than one character
    if (currentInput.value.length > 1) {
      currentInput.value = "";
      return;
    }

    // Enable next input and focus if current input is filled
    if (nextInput && nextInput.hasAttribute("disabled") && currentInput.value !== "") {
      nextInput.removeAttribute("disabled");
      nextInput.focus();
    }

    // Handle Backspace key
    if (e.key === "Backspace") {
      inputs.forEach((inp, index2) => {
        if (index1 <= index2 && prevInput) {
          inp.setAttribute("disabled", true);
          inp.value = "";
          prevInput.focus();
        }
      });
    }

    // Enable button if all inputs are filled
    if (!inputs[3].disabled && inputs[3].value !== "") {
      button.classList.add("active");
      return;
    }
    button.classList.remove("active");
  });
});

// Focus the first input on page load
window.addEventListener("load", () => inputs[0].focus());

// Countdown logic for the Resend OTP button
document.addEventListener("DOMContentLoaded", () => {
  let countdown = 30;

  const startCountdown = () => {
    resendButton.disabled = true; // Disable the button initially
    const countdownInterval = setInterval(() => {
      if (countdown > 0) {
        resendButton.textContent = `Resend OTP (${countdown}s)`;
        countdown--;
      } else {
        clearInterval(countdownInterval); // Stop countdown
        resendButton.textContent = "Resend OTP";
        resendButton.disabled = false; // Enable the button
      }
    }, 1000);
  };

  // Start the countdown when the page loads
  startCountdown();

  // Add a click event to restart the countdown when the button is clicked
  resendButton.addEventListener("click", () => {
    countdown = 30; // Reset countdown
    startCountdown(); // Restart countdown
  });
});
