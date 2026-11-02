# Learn the system by operating it

HELTEMES Evidence is Fischer Heltemes's original security-engineering portfolio project. This learning path develops the ability to operate, explain, extend, and maintain the system through specific demonstrations.

The starting point used here is Security+ completed, CCNA in progress, early CS50 C, and developing Python/Linux skills. Adjust the pace to your current understanding. Keep CCNA and CS50 moving alongside this project.

## The teaching loop

Work on one scenario at a time:

1. Predict what will happen before running it.
2. Run the smallest useful experiment in a separate practice data directory.
3. Name the relevant concept and the decisive clue in the result.
4. Explain the path through the actual code in your own words.
5. Change one condition and repeat without a copied answer.
6. Record what you did, what help you received, and what you can now demonstrate.

Use walkthroughs, references, tools, and review to support learning. For each change, read the diff, run the relevant check, and explain why the result supports the claim. A green test result does not by itself establish understanding. Guided walkthroughs can proceed step by step without stopping for questions when that is the preferred pace.

## Eight lessons

| Lesson | Concrete task | Demonstration that earns completion |
| --- | --- | --- |
| 1. Input → processing → output | Run a demo collection in a practice directory and open its dashboard | Identify input data, processing, stored output, and displayed output; distinguish the program from the data |
| 2. Python and JSON | Read one synthetic filing record and follow its fields into the application | Explain a dictionary, a list, a loop, and a missing-field check using the real code |
| 3. DNS, HTTPS, and failure | Trace a live request through the collector; study a timeout or rejected-request test | Distinguish name resolution, connection, TLS, HTTP status, and invalid content from their evidence |
| 4. Provenance, hashes, and checkpoints | Compare timestamps, initialize a practice checkpoint, then alter a disposable copy | Distinguish byte checks from a signature and separately pinned reference; explain what each detects and what remains trusted |
| 5. SQLite and duplicate handling | Collect demo data twice and inspect the resulting records | Explain a record's identity and distinguish stored filings from collection attempts |
| 6. Access boundaries | Inspect the localhost server, collector/custodian accounts, operator signing step, and cloud permission definitions | Explain which actions the collector is denied, why the separate trust record matters, and why the administrator remains trusted |
| 7. Recovery and incidents | Save a checkpoint receipt separately, create a protected backup, restore to a new directory, and verify | Recover without overwriting the original; explain why the exact independently retained receipt is needed and what an older backup represents |
| 8. Infrastructure as code | Read the Terraform design and a deployment plan when credentials are available | Explain planned resources, permission scope, recurring costs, and how collection is stopped |

The dashboard's lesson cards give an exercise and transfer check for each topic. Do not mark a lesson complete merely because its code exists.

For the local security exercises, follow [LOCAL_PROTECTION.md](LOCAL_PROTECTION.md) with practice data. Observe these cases: a byte edit; a byte edit plus changed database hash; new valid collection records; and an older archive paired with a newer trusted receipt. Keep the ordinary consistency result separate from the signed-checkpoint status. Changes to code or successful automated tests do not automatically complete any lesson.

## First session: run and explain

From the project directory:

```sh
python3 -m heltemes --data-dir work/lesson-01 demo
python3 -m heltemes --data-dir work/lesson-01 verify
python3 -m heltemes --data-dir work/lesson-01 serve --port 8766
```

Open `http://127.0.0.1:8766` in your browser. Port 8765 belongs to the managed dashboard. Stop this separate practice server with Control-C when finished.

Explain this before moving on: **The demo command reads synthetic input, processes it into evidence and records, and saves those outputs. The server reads the saved outputs for the browser.** Find the code that establishes each part. Then change only the port and explain why the stored evidence is unchanged.

This lesson requires no SEC contact, paid account, or AWS deployment. A working demo is evidence of local program behavior, not a successful live SEC collection.

## Contribution and learning log

Keep this table in your own working notes. Preserve previous entries instead of editing them to imply you knew something earlier.

| Date | Task or change | My contribution | Tools and references used | Evidence | Can explain and repeat unaided? | Next transfer check |
| --- | --- | --- | --- | --- | --- | --- |
| YYYY-MM-DD | Example: restored a practice backup | State exactly what you did | Record relevant tools, references, or review | Command output, test result, or screenshot path | Yes / partly / not yet, with reason | A different failure or input |

Record unexpected results as useful evidence. Ask for a hint first, then an explanation, then an implementation if needed. These are different levels of assistance.

## Resume and interview use

This can become a credible portfolio project because it joins networking, programming, data integrity, security, and operations around a real need. The strength depends on demonstrated depth and accurate claims. It does not establish trading skill, hiring outcomes, or readiness to operate a public production service.

Project description: **“HELTEMES Evidence — an original Python security-engineering portfolio project for SEC evidence collection, signed integrity checkpoints, and crash-safe key recovery.”** Describe cloud deployment as prepared until it has been deployed and verified.

For an individual contribution, use: **“Implemented [specific contribution] and demonstrated [measured result] in HELTEMES Evidence.”** Fill in only work and results you can substantiate. Say “deployed on AWS” only after an actual deployment and live checks. Say “automated monitoring” only when a functioning monitor and notification path have been tested.

For an interview, prepare one short story each about a design tradeoff, a failure you diagnosed, and a change you made. Show the decisive evidence and explain the limitations. That is how broad interests become a defensible engineering skill set.
