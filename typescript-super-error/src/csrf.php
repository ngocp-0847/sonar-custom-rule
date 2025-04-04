<?php

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [
        'api/*'
    ]; // Sensitive; disable CSRF protection for a list of routes
}