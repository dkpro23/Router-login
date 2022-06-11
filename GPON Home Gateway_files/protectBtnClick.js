function protectBtnClick(btn) {
	var links = document.getElementsByName(btn);
	for (var i = 0; i < links.length; i++) {
		if (document.addEventListener) {//for ie9+
			links[i].addEventListener('dblclick', function (e) {//To prevent Double-click the href!
				e.preventDefault();
			}, false);
			links[i].onclick = function () {//to allow a single click
				this.onclick = function (e) {
					e.preventDefault();
				}
			}
		} else if (document.attachEvent) {//for ie 7,8
			links[i].attachEvent('ondblclick', function (e) {//To prevent Double-click the href!
				event.returnValue = false;
			}, false);
			links[i].onclick = function () {//to allow a single click
				this.onclick = function (e) {
					event.returnValue = false;
				}
			}
		}
	}
}