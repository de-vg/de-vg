require('dotenv').config();

import fetch from "node-fetch";

export async function checkUrl(url: string) {
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${process.env.VIRUSTOTAL_KEY}&resource=${url}`);
    const json = await response.json();
    if(json.positives >= 1) {
        // Return false if url is NOT safe
        return false;
    } else  {
        return true;
    }
}