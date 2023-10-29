// import axios from 'axios';
const axios = require('axios');
const apiKey = require('./apiKeys.json').virustotal;

const options = (hash) => {
  return {
    method: 'GET',
    url: `https://www.virustotal.com/api/v3/files/${hash}`,
    headers: {
      accept: 'application/json',
      'x-apikey': apiKey
    }
  }
};

const hash = 'c0202cf6aeab8437c638533d14563d35'; // change this

const reportFromHash = (hash) => {
  axios
  .request(options(hash))
  .then(function (response) {
    const vt_res = response.data.data;
    console.log(`reputation: ${vt_res.attributes.reputation}`);
    console.log(`score: ${vt_res.attributes.last_analysis_stats.malicious}`);
  })
  .catch(function (error) {
    console.error(error);
  });
};

reportFromHash(hash);
