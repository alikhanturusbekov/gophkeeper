package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alikhanturusbekov/gophkeeper/internal/client/usecase"
	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	"github.com/alikhanturusbekov/gophkeeper/pkg/version"
)

// App is the root CLI application. It holds a cobra root command and the client use-case for all operations
type App struct {
	uc   *usecase.SecretUseCase
	root *cobra.Command
}

// NewApp constructs an App, wiring all sub-commands
func NewApp(uc *usecase.SecretUseCase) *App {
	a := &App{uc: uc}
	a.root = a.buildRoot()
	return a
}

// Execute parses os.Args and runs the selected command
func (a *App) Execute() error {
	return a.root.Execute()
}

// buildRoot creates the cobra root command and attaches all sub-commands.
func (a *App) buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper is a secure client-server password manager",
		Long:  `GophKeeper lets you store and retrieve passwords, binary files, and bank-card details securely.`,
	}
	root.AddCommand(
		versionCmd(),
		a.registerCmd(),
		a.loginCmd(),
		a.syncCmd(),
		a.listCmd(),
		a.getCmd(),
		a.addCmd(),
		a.deleteCmd(),
	)
	return root
}

// versionCmd prints the binary version and build date injected at compile time
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Info())
		},
	}
}

// registerCmd creates a new account on the remote server
func (a *App) registerCmd() *cobra.Command {
	var login, password string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a new GophKeeper account on the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, ok := a.uc.GetServer()
			if !ok {
				return fmt.Errorf("no server client configured")
			}
			token, err := srv.Register(context.Background(), login, password)
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}
			uid, err := a.uc.GetAuth().Validate(token)
			if err != nil {
				return fmt.Errorf("token from server invalid: %w", err)
			}
			a.uc.SetSession(uid, token)
			fmt.Printf("Registered successfully (userID: %s)\n", uid)
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "Account login name (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Master password (required)")
	cmd.MarkFlagRequired("login")
	cmd.MarkFlagRequired("password")
	return cmd
}

// loginCmd authenticates against the server and stores the JWT session
func (a *App) loginCmd() *cobra.Command {
	var login, password string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the GophKeeper server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, ok := a.uc.GetServer()
			if !ok {
				return fmt.Errorf("no server client configured")
			}
			token, err := srv.Login(context.Background(), login, password)
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}
			uid, err := a.uc.GetAuth().Validate(token)
			if err != nil {
				return fmt.Errorf("token from server invalid: %w", err)
			}
			a.uc.SetSession(uid, token)
			fmt.Fprintln(cmd.OutOrStdout(), "Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "Login name (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Master password (required)")
	cmd.MarkFlagRequired("login")
	cmd.MarkFlagRequired("password")
	return cmd
}

// syncCmd pushes local changes to the server and pulls the authoritative list
func (a *App) syncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronise local cache with the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.uc.Sync(context.Background()); err != nil {
				return fmt.Errorf("sync: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Sync completed successfully.")
			return nil
		},
	}
}

// listCmd prints a table of all locally cached secrets (names and kinds only payloads are not decrypted)
func (a *App) listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all stored secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			secrets, err := a.uc.List(context.Background())
			if err != nil {
				return err
			}
			if len(secrets) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No secrets found. Use 'gophkeeper add' to create one.")
				return nil
			}
			fmt.Printf("%-36s  %-20s  %-12s  %s\n", "ID", "NAME", "KIND", "METADATA")
			fmt.Println("-------------------------------------------------------------------------------------")
			for _, s := range secrets {
				fmt.Fprintf(cmd.OutOrStdout(), "%-36s  %-20s  %-12s  %s\n", s.ID, s.Name, string(s.Kind), s.Metadata)
			}
			return nil
		},
	}
}

// getCmd decrypts and prints a single secret's payload as pretty JSON
func (a *App) getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <secret-id>",
		Short: "Decrypt and display a secret's payload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secrets, err := a.uc.List(context.Background())
			if err != nil {
				return err
			}

			var target *domain.Secret
			for _, s := range secrets {
				if s.ID == args[0] {
					target = s
					break
				}
			}
			if target == nil {
				return fmt.Errorf("secret %q not found locally; try 'gophkeeper sync' first", args[0])
			}

			var payload interface{}
			switch target.Kind {
			case domain.KindCredential:
				var v domain.Credential
				if err := a.uc.Decrypt(target.EncryptedData, &v); err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				payload = v
			case domain.KindText:
				var v domain.TextData
				if err := a.uc.Decrypt(target.EncryptedData, &v); err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				payload = v
			case domain.KindBinary:
				var v domain.BinaryData
				if err := a.uc.Decrypt(target.EncryptedData, &v); err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				payload = v
			case domain.KindCard:
				var v domain.CardData
				if err := a.uc.Decrypt(target.EncryptedData, &v); err != nil {
					return fmt.Errorf("decrypt: %w", err)
				}
				payload = v
			default:
				return fmt.Errorf("unknown kind %q", target.Kind)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(payload)
		},
	}
}

// addCmd groups the add sub-commands
func (a *App) addCmd() *cobra.Command {
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a new secret (credential | text | binary | card)",
	}
	add.AddCommand(
		a.addCredentialCmd(),
		a.addTextCmd(),
		a.addBinaryCmd(),
		a.addCardCmd(),
	)
	return add
}

// addCredentialCmd stores an encrypted login/password pair
func (a *App) addCredentialCmd() *cobra.Command {
	var name, login, password, meta string
	cmd := &cobra.Command{
		Use:   "credential",
		Short: "Store a login/password credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.uc.AddCredential(context.Background(), name, login, password, meta)
			if err != nil {
				return err
			}
			fmt.Printf("Credential stored.  ID: %s\n", s.ID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "Label (required)")
	cmd.Flags().StringVarP(&login, "login", "l", "", "Login / username (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password (required)")
	cmd.Flags().StringVarP(&meta, "meta", "m", "", "Optional metadata (website, notes, …)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("login")
	cmd.MarkFlagRequired("password")
	return cmd
}

// addTextCmd stores arbitrary encrypted text
func (a *App) addTextCmd() *cobra.Command {
	var name, content, meta string
	cmd := &cobra.Command{
		Use:   "text",
		Short: "Store arbitrary text data",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.uc.AddText(context.Background(), name, content, meta)
			if err != nil {
				return err
			}
			fmt.Printf("Text stored.  ID: %s\n", s.ID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "Label (required)")
	cmd.Flags().StringVarP(&content, "content", "c", "", "Text content (required)")
	cmd.Flags().StringVarP(&meta, "meta", "m", "", "Optional metadata")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("content")
	return cmd
}

// addBinaryCmd reads a file and stores its encrypted contents
func (a *App) addBinaryCmd() *cobra.Command {
	var name, filePath, meta string
	cmd := &cobra.Command{
		Use:   "binary",
		Short: "Store binary data from a local file",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("read file %q: %w", filePath, err)
			}
			s, err := a.uc.AddBinary(context.Background(), name, filePath, data, meta)
			if err != nil {
				return err
			}
			fmt.Printf("Binary data stored.  ID: %s\n", s.ID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "Label (required)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to file (required)")
	cmd.Flags().StringVarP(&meta, "meta", "m", "", "Optional metadata")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("file")
	return cmd
}

// addCardCmd stores encrypted payment-card details
func (a *App) addCardCmd() *cobra.Command {
	var name, number, holder, expiry, cvv, meta string
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Store bank card details",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := a.uc.AddCard(context.Background(), name, number, holder, expiry, cvv, meta)
			if err != nil {
				return err
			}
			fmt.Printf("Card stored.  ID: %s\n", s.ID)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "name", "n", "", "Label (required)")
	cmd.Flags().StringVarP(&number, "number", "N", "", "Card number (required)")
	cmd.Flags().StringVarP(&holder, "holder", "H", "", "Cardholder name (required)")
	cmd.Flags().StringVarP(&expiry, "expiry", "e", "", "Expiry date MM/YY (required)")
	cmd.Flags().StringVarP(&cvv, "cvv", "c", "", "CVV (required)")
	cmd.Flags().StringVarP(&meta, "meta", "m", "", "Optional metadata")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("number")
	cmd.MarkFlagRequired("holder")
	cmd.MarkFlagRequired("expiry")
	cmd.MarkFlagRequired("cvv")
	return cmd
}

// deleteCmd soft-deletes a secret by ID
func (a *App) deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <secret-id>",
		Short: "Delete a secret by its ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.uc.Delete(context.Background(), args[0]); err != nil {
				return err
			}
			fmt.Printf("Secret %s deleted.\n", args[0])
			return nil
		},
	}
}
