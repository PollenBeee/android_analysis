Java.perform(() => {
    const OkHttpClient = Java.use('okhttp3.OkHttpClient');
    const Request = Java.use('okhttp3.Request');

    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        console.log("[*] OkHttp Request URL: " + request.url().toString());
        return this.newCall(request);
    };
});
