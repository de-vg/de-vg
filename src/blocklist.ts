import {promisify} from "util";
import fs from "fs";

const readFile: Function = promisify(fs.readFile);

export async function checkUrlShortener(url: string) {
    if((await readFile("blocklists/url_shorteners.txt")).includes(`${new URL(url).hostname}`)) {
        return false;
    } else return true;
}

export async function checkPornTop1Million(url: string) {
    if((await readFile("blocklists/porn_top1m.txt")).includes(`${new URL(url).hostname}`)) {
        return false;
    } else return true;
}