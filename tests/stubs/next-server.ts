export type NextRequest = Request;

export class NextResponse {
  status: number;
  headers: Headers;
  private bodyValue: any;

  constructor(body?: any, init: { status?: number; headers?: HeadersInit } = {}) {
    this.status = init.status ?? 200;
    this.headers = new Headers(init.headers);
    this.bodyValue = body ?? null;
  }

  static json(data: any, init: { status?: number; headers?: HeadersInit } = {}) {
    const headers = new Headers(init.headers);
    if (!headers.has('content-type')) {
      headers.set('content-type', 'application/json');
    }
    const response = new NextResponse(JSON.stringify(data), { ...init, headers });
    return response;
  }

  async json() {
    if (typeof this.bodyValue === 'string') {
      return JSON.parse(this.bodyValue);
    }
    return this.bodyValue;
  }

  async text() {
    if (typeof this.bodyValue === 'string') {
      return this.bodyValue;
    }
    return JSON.stringify(this.bodyValue);
  }
}
