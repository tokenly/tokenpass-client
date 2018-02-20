@extends('layouts.base')

@section('content')
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-9">
                <h2>Hello {{$user['name']}}</h2>

                <div class="spacer1"></div>

                <p>You are signed in as user <span class="username">{{$user['username']}}</span>.</p>

                <div class="spacer1"></div>

                <a href="/account/logout" class="btn btn-success">Logout</a>
            </div>
        </div>
    </div>
@stop
