Java.perform(() => {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            console.log(className);
        },
        onComplete: function() {
            console.log("=== Finished Listing Classes ===");
        }
    });
});

// rpc.exports = {
//     listclasses: function () {
//         var result = [];
//         Java.perform(function () {
//             var classes = Java.enumerateLoadedClassesSync();
//             for (var i = 0; i < classes.length; i++) {
//                 result.push(classes[i]);
//             }
//         });
//         return result;
//     }
// };
