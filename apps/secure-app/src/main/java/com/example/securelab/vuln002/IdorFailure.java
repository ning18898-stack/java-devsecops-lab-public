package com.example.securelab.vuln002;
public final class IdorFailure extends RuntimeException {
    private final int status;
    public IdorFailure(int status) { this.status=status; }
    public int status() { return status; }
}
