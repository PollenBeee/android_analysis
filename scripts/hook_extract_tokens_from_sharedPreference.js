Java.perform(() => {
    const SharedPreferences = Java.use('android.content.SharedPreferences');

    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
        if (key.toLowerCase().indexOf('token') !== -1 || key.toLowerCase().indexOf('auth') !== -1) {
            const value = this.getString(key, defValue);
            console.log(`[+] SharedPreferences key: ${key}, value: ${value}`);
            return value;
        }
        return this.getString(key, defValue);
    };
});
