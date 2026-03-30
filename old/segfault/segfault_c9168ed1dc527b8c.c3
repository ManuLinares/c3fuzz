// #target: macos-x64
module foo;
extern fn void printf(float[<2>] clamped = zero2.clamp_length(1.0f, 2.0f),...);

fn int? foo() { return 1; }

macro @foo_test(int i; @body())
{
	defer printf("%d\n", i);
	@body();
	defer printf("2:%d\n", i);
}

macro foo_defer()
{
	defer printf("A\n");
	printf("B\n");
	defer printf("C\n");
}
fn void main()
{
    foo_defer();
	@foo_test(34) {
		defer printf("inside_defer\n");
	};
	while (1)
	{
		defer printf("outside\n");
		@foo_test(3)
		{
			defer printf("Inside will it jump?\n");
			printf("3-test\n");
			break;
		};
	}
	while (1)
	{
		defer printf("outside2\n");
		printf("--\n");
		@foo_test(3)
		{
			defer printf("Inside will it jump?\n");
			printf("--3\n");
			return;
		};
	}
}