package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"go.temporal.io/api/workflow/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

func stat() {
	c, err := client.Dial(client.Options{})
	if err != nil {
		log.Fatalf("Failed to dial Temporal: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Query for running top-level workflows only (no parents)
	query := "ExecutionStatus='Running' AND ParentWorkflowId IS NULL"
	response, err := c.ListWorkflow(ctx, &workflowservice.ListWorkflowExecutionsRequest{Query: query})
	if err != nil {
		log.Fatalf("Failed listing workflows: %v", err)
	}

	for _, info := range response.Executions {
		topID := info.Execution.WorkflowId
		topType := info.Type.Name
		fmt.Printf("\n====== Top WF: %s [%s] ======\n", topType, topID)

		// Describe to pull current activity telemetry
		desc, err := c.DescribeWorkflowExecution(ctx, info.Execution.WorkflowId, info.Execution.RunId)
		if err != nil {
			continue
		}
		for _, act := range desc.PendingActivities {
			showActivity(act)
		}
		// Find children pointing back to this parent
		childQuery := fmt.Sprintf("ExecutionStatus='Running' AND ParentWorkflowId='%s'", topID)
		childResponse, err := c.ListWorkflow(ctx, &workflowservice.ListWorkflowExecutionsRequest{Query: childQuery})
		if err != nil {
			fmt.Printf("  Error fetching children: %v\n", err)
			continue
		}

		if len(childResponse.Executions) == 0 {
			fmt.Println("  (No active children)")
			continue
		}

		for _, child := range childResponse.Executions {
			childID := child.Execution.WorkflowId
			childRunID := child.Execution.RunId
			childType := child.Type.Name

			// Describe to pull current activity telemetry
			desc, err := c.DescribeWorkflowExecution(ctx, childID, childRunID)
			if err != nil {
				continue
			}

			fmt.Printf("  └── Child: %s [%s]\n", childType, childID)

			if len(desc.PendingActivities) == 0 {
				fmt.Println("        (No pending activities)")
				continue
			}

			for _, act := range desc.PendingActivities {
				showActivity(act)
			}
		}
	}
}

func showActivity(act *workflow.PendingActivityInfo) {
	actName := act.ActivityType.Name
	attempt := act.Attempt

	// Infer max attempts boundary text safely
	maxAttempts := "∞"
	if act.MaximumAttempts > 0 {
		maxAttempts = fmt.Sprintf("%d", act.MaximumAttempts)
	}

	// Abbreviate and truncate raw argument string payloads
	rawArgs := "[]"
	if act.HeartbeatDetails != nil {
		rawArgs = string(act.HeartbeatDetails.Payloads[0].Data)
	} else if act.LastFailure != nil {
		rawArgs = act.LastFailure.Message
	}
	abbrArgs := abbrev(rawArgs, 45)

	fmt.Printf("        --> Activity: %s (try %d/%s) args: %s\n",
		actName, attempt, maxAttempts, abbrArgs)
}

func abbrev(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
