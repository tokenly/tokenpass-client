# Migrating from v0.3.0 and earlier to v1.0.0

- For laravel projects, tempoarily disable any `TokenlyAccountsServiceProvider` reference in app.php
- Change composer dependencies.  Run `composer remove tokenly/accounts-client && composer require 'tokenly/tokenpass-client:^1.0.0'`
- For laravel projects, add a `TokenpassServiceProvider` reference in app.php
- Change all class names.  
    - Replace `TokenlyAccounts` with `Tokenpass`.
    - Replace `Accounts` with `Tokenpass`
    - Replace `AccountsAPI` with `TokenpassAPI`
- Change all class namespaces.  Replace `AccountsClient` with `TokenpassClient`
- Rename your configuration file from `tokenlyaccounts.php` to `tokenpass.php`
- Change configuration variables from `TOKENLY_ACCOUNTS_` to `TOKENPASS_`
- Change URL references from `https://accounts.tokenly.com` to `https://tokenpass.tokenly.com`

