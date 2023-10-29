const fetchCVSSData = async (cveId) => {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cve/1.0/${cveId}`;
    const response = await fetch(url);

    if (response.ok) {
      const cveData = await response.json();
      const cvssV3 = cveData.result.CVE_Items[0].impact.baseMetricV3;
      if (cvssV3) {
        return cvssV3.cvssV3.baseScore;
      } else {
        throw new Error(`No CVSS score data available for CVE ID ${cveId}`);
      }
    } else {
      throw new Error(`Error fetching data for CVE ID ${cveId}`);
    }
  } catch (error) {
    console.error(`An error occurred: ${error.message}`);
  }
}
  
const cveId = 'CVE-2019-1010218';
// fetchCVSSData(cveId).then(score => console.log(score));
const JIRA_BASE_URL = 'https[:]//your-jira-instance.net';
const JIRA_API_TOKEN = 'YOUR_API_TOKEN';
const authHeaders = {
  headers: {
    'Authorization': `Bearer ${JIRA_API_TOKEN}`,
    'Content-Type': 'application/json',
  },
};
  
const updateLabel = async (issueKey) => {
  fetchCVSSData(cveId).then(async score => {
    const NEW_LABEL = `CVSS: ${score}`;
    try {
      const jiraIssueUrl = `${JIRA_BASE_URL}/rest/api/2/issue/${ISSUE_KEY}`;
      const response = await fetch(jiraIssueUrl, authHeaders);
      const issueData = await response.json();
      const updateData = {
        update: {
          labels: [
            {
              add: NEW_LABEL,
            },
          ],
        },
      };

      if (!issueData.fields.labels.includes('CVSS')) {
        const updateResponse = await fetch(jiraIssueUrl, {
          method: 'PUT',
          authHeaders,
          body: JSON.stringify(updateData),
        });

        if (updateResponse.status === 204) {
          console.log(`Label "${NEW_LABEL}" added to issue ${ISSUE_KEY}`);
        } else {
          throw new Error(`Failed to update label: ${response.statusText}`);
        }
      }
    } catch (error) {
        console.error(`An error occurred: ${error.message}`);
    }
  });
};
  
updateLabel();
