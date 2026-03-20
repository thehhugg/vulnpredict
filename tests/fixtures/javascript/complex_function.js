// Complex function with deep nesting
function complexProcessor(data) {
    if (data) {
        for (var i = 0; i < data.length; i++) {
            if (data[i].active) {
                for (var j = 0; j < data[i].items.length; j++) {
                    if (data[i].items[j].valid) {
                        console.log(data[i].items[j]);
                    }
                }
            }
        }
    }
}

// Simple function
function simpleHelper(x) {
    return x * 2;
}
