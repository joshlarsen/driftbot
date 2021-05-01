/**
 * Handle GitHub issues for monitored sites.
 * 
 * Workflow:
 *  If the site fails a check, create an issue and label it
 *  according to the check type (e.g. script-hosts).
 * 
 *  If the site passes a check and there is an existing open
 *  issue, label it 'resolved'.
 * 
 *  If the site passess a check and there is an existing open
 *  issue with the 'resolved' label, close it. This provides
 *  a simple way to handle 'flapping' issues where a site's 
 *  hosts change often enough to cause issues to repeatedly 
 *  open & close.
 * 
 *  If the site fails a check and there is an existing open
 *  issue with the 'resolved' label, remove the label.
 */

const logger = require('./logger')
const auth = process.env.GITHUB_TOKEN
const owner = process.env.GITHUB_ACTOR
const github_repo = process.env.GITHUB_REPOSITORY
const repo = github_repo ? github_repo.split('/').pop() : ''
const server = process.env.GITHUB_SERVER_URL
const run_id = process.env.GITHUB_RUN_ID
const { Octokit } = require("@octokit/rest")
const octokit = new Octokit({ auth: auth })
const footer = run_id ? `\n\nView [logs](${server}/${github_repo}/actions/runs/${run_id}) from this job.` : ''

/**
 * Create a new issue
 * @param {object} opts
 */
async function create(opts) {
  const body = `[bot] observed hosts:\n\`\`\`\n${opts.hosts.join('\n')}\n\`\`\`${footer}`

  const resp = await octokit.rest.issues.create({
    owner: owner,
    repo: repo,
    title: `❗Unauthorized ${opts.title} sources detected.`,
    body: body,
    labels: [opts.label]
  })

  if (resp.status == 201) logger.log(`[github] created issue ${resp.data.number}`)
}

/**
 * Close an existing issue with a comment
 * @param {object} issue
 */
async function close(issue) {
  await comment(issue, 'no unauthorized hosts found')

  const resp = await octokit.rest.issues.update({
    owner: owner,
    repo: repo,
    issue_number: issue.number,
    state: 'closed'
  })

  if (resp.status == 200) logger.log(`[github] closing issue ${issue.number}`)
}

/**
 * Comment on an issue
 * @param {object} issue
 * @param {string} comment
 */
async function comment(issue, comment) {
  const resp = await octokit.rest.issues.createComment({
    owner: owner,
    repo: repo,
    issue_number: issue.number,
    body: `[bot] ${comment}.${footer}`
  })

  if (resp.status == 201) logger.log(`[github] commenting on issue ${issue.number}`)
}

/**
 * List issues of a certain type/label
 * @param {string} label
 * @return {array}
 */
async function list(label) {
  const resp = await octokit.rest.issues.listForRepo({
    owner: owner,
    repo: repo,
    state: 'open',
    labels: label
  })

  return resp.data
}

/**
 * Label an existing issue resolved, close it if already labeled
 * @param {object} issue
 */
async function mark(issue) {
  const labels = issue.labels.map(l => l.name)

  // if issue isn't labeled, label it
  if (!labels.includes('resolved')) {

    await comment(issue, 'no unauthorized hosts found')

    const resp = await octokit.rest.issues.addLabels({
      owner: owner,
      repo: repo,
      issue_number: issue.number,
      labels: ['resolved']
    })

    if (resp.status == 200) logger.log(`[github] added label on issue ${issue.number}`)
  } else {
    // issue is labeled, close it
    await close(issue)
  }
}

/**
 * Remove 'resolved' label from an existing issue
 * @param {object} issue
 */
async function unmark(issue) {
  const labels = issue.labels.map(l => l.name)

  // issue isn't labeled
  if (!labels.includes('resolved')) return

  await comment(issue, 'unauthorized hosts found')

  const resp = await octokit.rest.issues.removeLabel({
    owner: owner,
    repo: repo,
    issue_number: issue.number,
    name: 'resolved'
  })

  if (resp.status == 200) logger.log(`[github] removed label on issue ${issue.number}`)
}

module.exports = {
  create,
  mark,
  unmark,
  list
}
