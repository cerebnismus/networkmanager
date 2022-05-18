$(function () {
  $(".menu-link").click(function () {
   $(".menu-link").removeClass("is-active");
   $(this).addClass("is-active");
  });
 });
 
 $(function () {
  $(".main-header-link").click(function () {
   $(".main-header-link").removeClass("is-active");
   $(this).addClass("is-active");
  });
 });
 
 const dropdowns = document.querySelectorAll(".dropdown");
 dropdowns.forEach((dropdown) => {
  dropdown.addEventListener("click", (e) => {
   e.stopPropagation();
   dropdowns.forEach((c) => c.classList.remove("is-active"));
   dropdown.classList.add("is-active");
  });
 });
 
 $(".search-bar input")
  .focus(function () {
   $(".header").addClass("wide");
  })
  .blur(function () {
   $(".header").removeClass("wide");
  });
 
 $(document).click(function (e) {
  var container = $(".status-button");
  var dd = $(".dropdown");
  if (!container.is(e.target) && container.has(e.target).length === 0) {
   dd.removeClass("is-active");
  }
 });
 
 $(function () {
  $(".dropdown").on("click", function (e) {
   $(".content-wrapper").addClass("overlay");
   e.stopPropagation();
  });
  $(document).on("click", function (e) {
   if ($(e.target).is(".dropdown") === false) {
    $(".content-wrapper").removeClass("overlay");
   }
  });
 });
 
$(function () {
  // ADD
  $(".status-button.add").click(function () {
    $(".pop-up").addClass("visible");
  });

  // CANCEL
  $(".status-button.cancel").click(function () {
    $(".pop-up").removeClass("visible");
  });

  $(".pop-up .close").click(function () {
    $(".pop-up").removeClass("visible");
  });

/*
  // details formarly edit
  $(".status-button.details").click(function () {
    $(".pop-up").addClass("visible");
  });

  $(".pop-up .close").click(function () {
    $(".pop-up").removeClass("visible");
  });

  // DELETE   // TO:DO   ARE YOU SURE ??
  $(".status-button.delete").click(function () {
    $(".overlay-app").addClass("is-active");
  });

  $(".pop-up .close").click(function () {
    $(".overlay-app").removeClass("is-active");
  });
*/
});
 
const toggleButton = document.querySelector('.dark-light');

toggleButton.addEventListener('click', () => {
  document.body.classList.toggle('light-mode');
});

// Call a function every 60000 milliseconds (OR 60 seconds).
window.setInterval('refresh()', 60000);

// Refresh or reload page.
function refresh() {
  window.location.reload();
}

var myVar = setInterval(function() {
  myTimer();
}, 1000);

function myTimer() {
  var d = new Date();
  document.getElementById("h2-clock").innerHTML = d.toLocaleTimeString();
}

var date = new Date(),
  weekday = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"],
  day = weekday[date.getDay()],
  style = "color:#eee;text-shadow:0px 2px 2px rgba(0,0,0,0.9);";
document.getElementById(day).style.cssText = style;