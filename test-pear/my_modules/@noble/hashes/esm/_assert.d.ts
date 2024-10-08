declare function number(n: number): void;
declare function bool(b: boolean): void;
export declare function isBytes(a: unknown): a is Uint8Array;
declare function bytes(b: Uint8Array | undefined, ...lengths: number[]): void;
type Hash = {
    (data: Uint8Array): Uint8Array;
    blockLen: number;
    outputLen: number;
    create: any;
};
declare function hash(h: Hash): void;
declare function exists(instance: any, checkFinished?: boolean): void;
declare function output(out: any, instance: any): void;
export { number, bool, bytes, hash, exists, output };
declare const assert: {
    number: typeof number;
    bool: typeof bool;
    bytes: typeof bytes;
    hash: typeof hash;
    exists: typeof exists;
    output: typeof output;
};
export default assert;
//# sourceMappingURL=_assert.d.ts.map