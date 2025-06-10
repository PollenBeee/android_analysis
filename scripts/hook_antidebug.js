Java.perform(function () {
    var Debug = Java.use("android.os.Debug");

    Debug.isDebuggerConnected.implementation = function () {
        console.log("[*] Bypassing isDebuggerConnected()");
        return false; 
    };

    Debug.waitingForDebugger.implementation = function () {
        console.log("[*] Bypassing waitingForDebugger()");
        return false;
    };

    console.log('[*] Hook placed on android.os.Debug.isDebuggerConnected');
    console.log('[*] Hook placed on android.os.Debug.waitingForDebugger');
});