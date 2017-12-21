var ct_date = new Date(), 
	ctTimeMs = new Date().getTime(),
	ctMouseEventTimerFlag = true, //Reading interval flag
	ctMouseData = [],
	ctMouseDataCounter = 0;

function ctSetCookie(c_name, value) {
	document.cookie = c_name + "=" + encodeURIComponent(value) + "; path=/";
}

function apbct_attach_event_handler(elem, event, callback){
	if(typeof window.addEventListener == "function") elem.addEventListener(event, callback);
	else                                             elem.attachEvent(event, callback);
}

function apbct_remove_event_handler(elem, event, callback){
	if(typeof window.removeEventListener == "function") elem.removeEventListener(event, callback);
	else                                                elem.detachEvent(event, callback);
}

ctSetCookie("ct_ps_timestamp", Math.floor(new Date().getTime()/1000));
ctSetCookie("ct_fkp_timestamp", "0");
ctSetCookie("ct_pointer_data", "0");
ctSetCookie("ct_timezone", "0");

setTimeout(function(){
	ctSetCookie(ct_cookie_name, ct_cookie_value);
	ctSetCookie("ct_timezone", ct_date.getTimezoneOffset()/60*(-1));
},1000);

//Writing first key press timestamp
var ctFunctionFirstKey = function output(event){
	var KeyTimestamp = Math.floor(new Date().getTime()/1000);
	ctSetCookie("ct_fkp_timestamp", KeyTimestamp);
	ctKeyStopStopListening();
}

//Reading interval
var ctMouseReadInterval = setInterval(function(){
	ctMouseEventTimerFlag = true;
}, 150);
	
//Writting interval
var ctMouseWriteDataInterval = setInterval(function(){
	ctSetCookie("ct_pointer_data", JSON.stringify(ctMouseData));
}, 1200);

//Logging mouse position each 150 ms
var ctFunctionMouseMove = function output(event){
	if(ctMouseEventTimerFlag == true){
		
		ctMouseData.push([
			Math.round(event.pageY),
			Math.round(event.pageX),
			Math.round(new Date().getTime() - ctTimeMs)
		]);
		
		ctMouseDataCounter++;
		ctMouseEventTimerFlag = false;
		if(ctMouseDataCounter >= 100){
			ctMouseStopData();
		}
	}
}

//Stop mouse observing function
function ctMouseStopData(){
	apbct_remove_event_handler(window, "mousemove", ctFunctionMouseMove);
	clearInterval(ctMouseReadInterval);
	clearInterval(ctMouseWriteDataInterval);				
}

//Stop key listening function
function ctKeyStopStopListening(){
	apbct_remove_event_handler(window, "mousedown", ctFunctionFirstKey);
	apbct_remove_event_handler(window, "keydown", ctFunctionFirstKey);
}

apbct_attach_event_handler(window, "mousemove", ctFunctionMouseMove);
apbct_attach_event_handler(window, "mousedown", ctFunctionFirstKey);
apbct_attach_event_handler(window, "keydown", ctFunctionFirstKey);