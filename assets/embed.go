package assets

import "embed"

//go:embed go_templates/*
var EmailTemplates embed.FS
