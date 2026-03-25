const fs = require("fs");

const adjectives = JSON.parse(fs.readFileSync("util/adjectives.json", "utf-8"));
const nouns = JSON.parse(fs.readFileSync("util/nouns.json", "utf-8"));

function random(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

const result = `${random(adjectives)}-${random(nouns)}`;
console.log(result);