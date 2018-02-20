@extends('layouts.base')

@section('content')
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-9">
                <h2>Login or Register</h2>

                <p>You are not logged in yet.</p>

                <a href="/account/authorize" class="btn btn-primary">Login or Register Now</a>
            </div>
        </div>
    </div>
@stop
