---
import-schema:
  queues:
    type: array
    items:
      type: string
    required: true
  limit:
    type: integer
    default: 20
  note:
    type: string
    default: ""
safe-outputs:
  add-labels:
    allowed: ${{ github.aw.import-inputs.queues }}
    max-labels: 1
jobs:
  facts:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      json: ${{ steps.c.outputs.json }}
    steps:
      - id: c
        env:
          QUEUES: ${{ github.aw.import-inputs.queues }}
          LIMIT: ${{ github.aw.import-inputs.limit }}
        run: echo "json=$QUEUES" >> "$GITHUB_OUTPUT"
---
Limit is ${{ github.aw.import-inputs.limit }}. Note: ${{ github.aw.import-inputs.note }}
Facts: ${{ needs.facts.outputs.json }}
