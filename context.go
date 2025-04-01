package guard

import (
	"context"
)

type ctxKey string

const guardCtx ctxKey = "guard"

type contextData struct {
	accessCheckDisabled bool
}

func Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, guardCtx, &contextData{})
}

func DisableCheckPerms(ctx context.Context) {
	data := ctx.Value(guardCtx).(*contextData)
	data.accessCheckDisabled = true
}

func isCheckDisabled(ctx context.Context) bool {
	data, ok := ctx.Value(guardCtx).(*contextData)
	return ok && data.accessCheckDisabled
}
