function changeCancelbutton(e) {
    if (e.innerHTML == "Edit Store") {
        e.innerHTML = "Cancel Editing";
    } else {
        document.location.reload();
    }
}