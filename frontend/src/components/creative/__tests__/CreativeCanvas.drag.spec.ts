import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import CreativeCanvas from '@/components/creative/CreativeCanvas.vue'
import { CREATIVE_OUTPUT_DRAG_MIME, serializeCreativeOutputDrag } from '@/utils/creativeDrag'
import { outputAssetKey, type LocalAsset } from '@/utils/creativeLocalStore'

/**
 * CreativeCanvas.drag.spec.ts exercises external image drops, history output
 * placement, wheel navigation, touch zoom, and anchor positioning through the
 * mounted canvas component. Fabric and image decoding are lightweight fixtures,
 * while the tests dispatch browser events and inspect resulting transforms,
 * asset calls, and object metadata. The suite checks interaction calculations
 * and event routing without performing pixel rendering.
 */

/**
 * fabricState retains mocked canvases, decoded images, and pointer coordinates
 * for assertions after real component event handlers run.
 */
const fabricState = vi.hoisted(() => ({
  main: null as any,
  mask: null as any,
  images: [] as any[],
  scenePoint: { x: 200, y: 150 },
  viewportPoint: { x: 200, y: 150 },
}))

/**
 * storeMocks controls local persistence outcomes so drop handling can be tested
 * without opening a browser database.
 */
const storeMocks = vi.hoisted(() => ({
  saveAsset: vi.fn(),
  loadAsset: vi.fn(),
  loadSceneJson: vi.fn(),
  saveSceneJson: vi.fn(),
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('@/utils/creativeLocalStore', () => ({
  /**
   * LocalStoreQuotaError supplies the storage error identity used by the canvas
   * fixture.
   */
  LocalStoreQuotaError: class LocalStoreQuotaError extends Error {},
  loadAsset: storeMocks.loadAsset,
  loadSceneJson: storeMocks.loadSceneJson,
  saveAsset: storeMocks.saveAsset,
  saveSceneJson: storeMocks.saveSceneJson,
  localAssetKey: (kind: string, id: string) => `${kind}:local:${id}`,
  outputAssetKey: (runId: string, outputIndex: number) => `output:${runId}:${outputIndex}`,
}))

vi.mock('fabric', () => {
  /**
   * MockObject provides mutable scene geometry for the component's Fabric
   * interactions.
   */
  class MockObject {
    left = 0 // left scene coordinate
    top = 0 // top scene coordinate
    width = 0 // horizontal dimension pixels
    height = 0 // vertical dimension pixels
    scaleX = 1 // horizontal display scale
    scaleY = 1 // vertical display scale
    angle = 0 // object rotation degrees
    data?: Record<string, unknown> // custom scene object metadata
    selectable = true // object selection eligibility
    evented = true // object event eligibility

    /**
     * constructor initializes a fixture object from optional supplied properties.
     * Missing values retain the fixture defaults, while overrides let the component
     * construct helper rectangles with their own geometry and interaction flags.
     */
    constructor(values?: Record<string, unknown>) {
      if (values) Object.assign(this, values)
    }

    /**
     * set applies fixture properties to this object and returns the same instance.
     */
    set(values: Record<string, unknown>): this {
      Object.assign(this, values)
      return this
    }

    /**
     * setCoords supplies a no-op coordinate refresh for the simplified Fabric
     * fixture.
     */
    setCoords(): void {}

    /**
     * getBoundingRect returns translated dimensions scaled by the fixture's
     * horizontal and vertical factors.
     */
    getBoundingRect(): {
      left: number // left scene coordinate
      top: number // top scene coordinate
      width: number // horizontal dimension pixels
      height: number // vertical dimension pixels
    } {
      return {
        left: this.left,
        top: this.top,
        width: this.width * this.scaleX,
        height: this.height * this.scaleY,
      }
    }
  }

  /**
   * MockImage supplies fixed image dimensions and records simulated decoding
   * results.
   */
  class MockImage extends MockObject {
    width = 400 // horizontal dimension pixels
    height = 200 // vertical dimension pixels

    /**
     * getElement supplies fixed natural image dimensions for resolution and
     * placement assertions.
     */
    getElement(): Partial<HTMLImageElement> {
      return { naturalWidth: 400, naturalHeight: 200, width: 400, height: 200 }
    }

    /**
     * fromURL creates a decoded image fixture and records it for placement
     * assertions. URL bytes are not decoded in this substitute, keeping the test
     * focused on component ordering and metadata.
     */
    static async fromURL(): Promise<MockImage> {
      const image = new MockImage()
      fabricState.images.push(image)
      return image
    }
  }

  /**
   * MockCanvas provides the scene and viewport operations exercised by mounted
   * canvas tests.
   */
  class MockCanvas {
    upperCanvasEl = document.createElement('canvas') // canvas interaction element
    viewportTransform: [number, number, number, number, number, number] = [1, 0, 0, 1, 0, 0] // current affine viewport transform
    width = 800 // horizontal dimension pixels
    height = 600 // vertical dimension pixels
    backgroundColor = '' // canvas background color
    objects: MockObject[] = [] // ordered shared scene objects
    active: MockObject | null = null // currently selected fixture object
    listeners: Record<string, Array<(event: any) => void>> = {} // registered fixture event handlers

    /**
     * constructor registers this fixture as the main canvas or its mask overlay.
     * The first instance occupies the main slot, and the next instance lets tests
     * inspect overlay behavior separately.
     */
    constructor() {
      if (!fabricState.main) fabricState.main = this
      else fabricState.mask = this
    }

    /**
     * on appends a handler to the fixture's listeners for one event name.
     */
    on(name: string, handler: (event: any) => void): void {
      this.listeners[name] = [...(this.listeners[name] ?? []), handler]
    }
    /**
     * emit invokes the listeners registered for a simulated Fabric event name.
     */
    emit(name: string, event: any): void {
      this.listeners[name]?.forEach((handler) => handler(event))
    }
    /**
     * getWidth returns the fixture viewport width used by canvas placement.
     */
    getWidth(): number {
      return this.width
    }
    /**
     * getHeight returns the fixture viewport height used by canvas placement.
     */
    getHeight(): number {
      return this.height
    }
    /**
     * getZoom reads the horizontal scale from the fixture viewport transform.
     */
    getZoom(): number {
      return this.viewportTransform[0]
    }
    getScenePoint = vi.fn(() => ({
      x: (fabricState.viewportPoint.x - this.viewportTransform[4]) / this.getZoom(),
      y: (fabricState.viewportPoint.y - this.viewportTransform[5]) / this.getZoom(),
    })) // mock scene coordinate conversion
    /**
     * setViewportTransform stores the supplied transform tuple as the fixture
     * viewport state. The tuple remains shared, matching the direct mutations
     * inspected by these tests rather than creating an independent copy.
     */
    setViewportTransform(value: [number, number, number, number, number, number]): void {
      this.viewportTransform = value
    }
    zoomToPoint = vi.fn((_point: MockPoint, zoom: number): void => {
      this.viewportTransform[0] = zoom
      this.viewportTransform[3] = zoom
    }) // mock viewport zoom operation
    /**
     * setDimensions updates the fixture viewport size from the supplied width and
     * height.
     */
    setDimensions(value: {
      width: number // horizontal dimension pixels
      height: number // vertical dimension pixels
    }): void {
      this.width = value.width
      this.height = value.height
    }
    /**
     * requestRenderAll accepts render requests without drawing pixels in the
     * fixture.
     */
    requestRenderAll(): void {}
    /**
     * add appends shared scene objects to the fixture's ordered object list.
     */
    add(...objects: MockObject[]): void {
      this.objects.push(...objects)
    }
    /**
     * remove filters specified object identities from the fixture scene list.
     */
    remove(...objects: MockObject[]): void {
      this.objects = this.objects.filter((object) => !objects.includes(object))
    }
    /**
     * setActiveObject stores one fixture object as the current canvas selection.
     */
    setActiveObject(object: MockObject): void {
      this.active = object
    }
    /**
     * getActiveObject returns the shared selected object or null when selection is
     * empty. The component can inspect its identity and metadata; clearing
     * selection leaves the object in the scene list.
     */
    getActiveObject(): MockObject | null {
      return this.active
    }
    /**
     * getActiveObjects wraps the selected fixture object in a new array when
     * present. An empty selection returns an empty array, while contained object
     * identities remain shared with the scene.
     */
    getActiveObjects(): MockObject[] {
      return this.active ? [this.active] : []
    }
    /**
     * discardActiveObject clears the fixture selection while retaining all scene
     * objects.
     */
    discardActiveObject(): void {
      this.active = null
    }
    /**
     * getObjects returns the fixture's shared array of current scene objects. The
     * component reads and filters these identities directly, so callers needing an
     * isolated list must create their own copy.
     */
    getObjects(): MockObject[] {
      return this.objects
    }
    /**
     * toObject returns an empty object list for snapshot calls in interaction
     * tests. Drag assertions inspect live fixture objects, so this substitute
     * deliberately supplies no serialized geometry for persistence verification.
     */
    toObject(): {
      objects: never[] // ordered shared scene objects
    } {
      return { objects: [] }
    }
    /**
     * clear empties the fixture scene list for reset and restoration assertions.
     */
    clear(): void {
      this.objects = []
    }
    /**
     * dispose accepts component cleanup without allocating browser drawing
     * resources in the fixture.
     */
    dispose(): void {}
  }

  /**
   * MockText represents runtime resolution labels within the lightweight Fabric
   * fixture.
   */
  class MockText extends MockObject {
    text: string // displayed fixture label text
    width = 40 // horizontal dimension pixels
    height = 12 // vertical dimension pixels

    /**
     * constructor records label text on the lightweight runtime tag fixture.
     */
    constructor(text: string) {
      super()
      this.text = text
    }
  }

  /**
   * MockBrush stores drawing properties used when the component enables painting.
   */
  class MockBrush {
    color = '' // configured brush color
    width = 0 // horizontal dimension pixels
    /**
     * constructor creates an empty brush fixture for component drawing-mode setup.
     */
    constructor() {}
  }

  /**
   * MockPoint carries viewport coordinates passed to the Fabric zoom substitute.
   */
  class MockPoint {
    /**
     * constructor stores the horizontal and vertical coordinates of a fixture
     * point.
     */
    constructor(
      public x: number, // horizontal point coordinate
      public y: number, // vertical point coordinate
    ) {}
  }

  return {
    Canvas: MockCanvas,
    FabricImage: MockImage,
    InteractiveFabricObject: { ownDefaults: {} },
    PencilBrush: MockBrush,
    Point: MockPoint,
    Rect: MockObject,
    StaticCanvas: MockCanvas,
    Text: MockText,
  }
})

/**
 * makeDropEvent creates a cancellable drop event with the supplied transfer
 * fixture.
 */
function makeDropEvent(dataTransfer: Record<string, unknown>): DragEvent {
  const event = new Event('drop', { bubbles: true, cancelable: true }) as DragEvent
  Object.defineProperty(event, 'dataTransfer', { value: dataTransfer })
  return event
}

/**
 * drop dispatches a transfer fixture to the canvas root and drains pending
 * promises. Callers can then assert asynchronous asset saving and placement
 * after the component's drop handler runs.
 */
async function drop(
  wrapper: ReturnType<typeof mount>,
  dataTransfer: Record<string, unknown>,
): Promise<void> {
  wrapper.find('.dot-grid').element.dispatchEvent(makeDropEvent(dataTransfer))
  await flushPromises()
}

/**
 * makeWheelEvent creates a cancellable wheel event with configurable delta and
 * modifier fields. Missing overrides use pixel scrolling at a fixed viewport
 * point, giving gesture assertions deterministic inputs.
 */
function makeWheelEvent(
  overrides: Partial<{
    deltaX: number // horizontal wheel movement
    deltaY: number // vertical wheel movement
    deltaMode: number // browser wheel measurement unit
    ctrlKey: boolean // pinch modifier flag
    offsetX: number // pointer horizontal viewport pixels
    offsetY: number // pointer vertical viewport pixels
  }> = {},
): WheelEvent {
  const event = new Event('wheel', { bubbles: true, cancelable: true }) as WheelEvent
  Object.defineProperties(event, {
    deltaX: { configurable: true, value: overrides.deltaX ?? 0 },
    deltaY: { configurable: true, value: overrides.deltaY ?? 0 },
    deltaMode: { configurable: true, value: overrides.deltaMode ?? 0 },
    ctrlKey: { configurable: true, value: overrides.ctrlKey ?? false },
    offsetX: { configurable: true, value: overrides.offsetX ?? 120 },
    offsetY: { configurable: true, value: overrides.offsetY ?? 80 },
  })
  return event
}

/**
 * emitWheel sends a wheel fixture through the registered Fabric mouse-wheel
 * handler.
 */
function emitWheel(overrides: Parameters<typeof makeWheelEvent>[0] = {}): WheelEvent {
  const event = makeWheelEvent(overrides)
  fabricState.main.emit('mouse:wheel', { e: event })
  return event
}

/**
 * makeTouchEvent creates a cancellable touch event carrying caller-supplied
 * client coordinates. Both touch collections use those coordinates so the
 * component's touch conversion can run in the DOM test environment.
 */
function makeTouchEvent(
  type: 'touchstart' | 'touchmove' | 'touchend' | 'touchcancel',
  touches: Array<{
    clientX: number // pointer horizontal client pixels
    clientY: number // pointer vertical client pixels
  }>,
): TouchEvent {
  const event = new Event(type, { bubbles: true, cancelable: true }) as TouchEvent
  Object.defineProperties(event, {
    touches: { configurable: true, value: touches },
    changedTouches: { configurable: true, value: touches },
  })
  return event
}

/**
 * mountCanvas mounts the real canvas component with crop and icon children
 * stubbed. It uses generation mode by default; the caller owns unmounting to
 * exercise listener and resource cleanup.
 */
function mountCanvas() {
  return mount(CreativeCanvas, {
    props: { operation: 'generate' },
    global: { stubs: { CropperModal: true, Icon: true } },
  })
}

describe('CreativeCanvas 拖放', () => {
  beforeEach(() => {
    fabricState.main = null
    fabricState.mask = null
    fabricState.images = []
    fabricState.scenePoint = { x: 200, y: 150 }
    fabricState.viewportPoint = { x: 200, y: 150 }
    storeMocks.saveAsset.mockReset().mockResolvedValue(undefined)
    storeMocks.loadAsset.mockReset().mockResolvedValue(null)
    storeMocks.loadSceneJson.mockReset().mockResolvedValue(null)
    storeMocks.saveSceneJson.mockReset().mockResolvedValue(undefined)
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: vi.fn(() => 'blob:creative-test'),
    })
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: vi.fn(),
    })
    vi.stubGlobal(
      'createImageBitmap',
      vi.fn(async () => ({
        width: 400,
        height: 200,
        close: vi.fn(),
      })),
    )
  })

  /**
   * An external PNG is dropped at the supplied scene point. The canvas must
   * persist source bytes and center the scaled image with a left-top origin.
   */
  it('将外部图片以落点为中心放到画布并保存为源素材', async () => {
    const wrapper = mountCanvas()
    expect(fabricState.main).not.toBeNull()
    expect(wrapper.find('.dot-grid').exists()).toBe(true)
    const file = new File(['image'], 'source.png', { type: 'image/png' })

    await drop(wrapper, {
      types: ['Files'],
      files: [file],
      getData: vi.fn(() => ''),
      dropEffect: 'copy',
    })

    expect(storeMocks.saveAsset).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'source', blob: file }),
    )
    expect(fabricState.images).toHaveLength(1)
    expect(fabricState.images[0]).toMatchObject({
      left: 150,
      top: 125,
      originX: 'left',
      originY: 'top',
      scaleX: 0.25,
      scaleY: 0.25,
    })
    wrapper.unmount()
  })

  /**
   * The first file in a multi-image drop fails during local saving. The remaining
   * file must still appear at its index-based diagonal offset from the drop
   * point.
   */
  it('多图拖入时从落点按固定间距斜向错开，单个保存失败不阻塞后续文件', async () => {
    storeMocks.saveAsset.mockRejectedValueOnce(new Error('quota')).mockResolvedValue(undefined)
    const wrapper = mountCanvas()
    const first = new File(['1'], 'first.png', { type: 'image/png' })
    const second = new File(['2'], 'second.webp', { type: 'image/webp' })

    await drop(wrapper, {
      types: ['Files'],
      files: [first, second],
      getData: vi.fn(() => ''),
      dropEffect: 'copy',
    })

    expect(fabricState.images).toHaveLength(1)
    expect(fabricState.images[0]).toMatchObject({ left: 190, top: 165 })
    wrapper.unmount()
  })

  /**
   * A history output is dropped into a zoomed and translated viewport. Placement
   * must use converted scene coordinates and retain its run, index, and asset
   * identity.
   */
  it('按当前场景坐标把历史 output 拖到落点并保留运行记录元数据', async () => {
    const runId = 'crun_0123456789abcdef'
    const asset: LocalAsset = {
      key: outputAssetKey(runId, 1),
      kind: 'output',
      blob: new Blob(['output'], { type: 'image/png' }),
      runId,
      outputIndex: 1,
      createdAt: Date.now(),
    }
    storeMocks.loadAsset.mockResolvedValue(asset)
    const wrapper = mountCanvas()
    fabricState.main.viewportTransform = [2, 0, 0, 2, 20, 30]
    fabricState.viewportPoint = { x: 620, y: 530 }

    await drop(wrapper, {
      types: [CREATIVE_OUTPUT_DRAG_MIME],
      files: [],
      getData: vi.fn((type: string) =>
        type === CREATIVE_OUTPUT_DRAG_MIME
          ? serializeCreativeOutputDrag({ runId, outputIndex: 1 })
          : '',
      ),
      dropEffect: 'copy',
    })

    expect(storeMocks.loadAsset).toHaveBeenCalledWith(asset.key)
    expect(fabricState.main.getScenePoint).toHaveBeenCalled()
    expect(fabricState.images[0]).toMatchObject({
      left: 250,
      top: 225,
      scaleX: 0.25,
      data: expect.objectContaining({ runId, outputIndex: 1, assetKey: asset.key }),
    })
    wrapper.unmount()
  })

  /**
   * An unsupported GIF is dropped through the normal file path. The component
   * must emit the unsupported-file message and create neither an asset write nor
   * image object.
   */
  it('不支持的文件类型不会创建画布对象并返回错误', async () => {
    const wrapper = mountCanvas()
    const file = new File(['gif'], 'image.gif', { type: 'image/gif' })

    await drop(wrapper, {
      types: ['Files'],
      files: [file],
      getData: vi.fn(() => ''),
      dropEffect: 'copy',
    })

    expect(storeMocks.saveAsset).not.toHaveBeenCalled()
    expect(fabricState.images).toHaveLength(0)
    expect(wrapper.emitted('error')).toEqual([['creative.error.dropUnsupported']])
    wrapper.unmount()
  })

  /**
   * A wheel event carries ordinary horizontal and vertical pixel deltas. It must
   * pan with the expected signs, consume the event, and leave the zoom operation
   * unused.
   */
  it('普通 wheel 只按跟手方向平移画布，不触发缩放', () => {
    const wrapper = mountCanvas()
    const event = emitWheel({ deltaX: 12, deltaY: -8 })

    expect(fabricState.main.viewportTransform).toEqual([1, 0, 0, 1, -12, 8])
    expect(fabricState.main.zoomToPoint).not.toHaveBeenCalled()
    expect(event.defaultPrevented).toBe(true)
    expect(event.cancelBubble).toBe(true)
    wrapper.unmount()
  })

  /**
   * Wheel fixtures supply line-mode and page-mode deltas to the same canvas. The
   * resulting translations must use configured line pixels and the corresponding
   * viewport dimensions.
   */
  it('按 wheel 单位将行和页换算为画布像素', () => {
    const wrapper = mountCanvas()
    emitWheel({ deltaX: 2, deltaY: 3, deltaMode: 1 })
    expect(fabricState.main.viewportTransform).toEqual([1, 0, 0, 1, -32, -48])

    fabricState.main.setViewportTransform([1, 0, 0, 1, 0, 0])
    emitWheel({ deltaX: 1, deltaY: 1, deltaMode: 2 })
    expect(fabricState.main.viewportTransform).toEqual([1, 0, 0, 1, -800, -600])
    wrapper.unmount()
  })

  /**
   * A control-modified wheel event represents a trackpad pinch at a specific
   * viewport point. The component must forward that point and its configured
   * exponential zoom factor.
   */
  it('ctrlKey wheel 以光标为中心缩放并使用加快后的灵敏度', () => {
    const wrapper = mountCanvas()
    const event = emitWheel({ deltaY: 10, ctrlKey: true, offsetX: 230, offsetY: 170 })
    const [point, zoom] = fabricState.main.zoomToPoint.mock.calls[0]

    expect(point).toMatchObject({ x: 230, y: 170 })
    expect(zoom).toBeCloseTo(0.995 ** 10, 10)
    expect(fabricState.main.viewportTransform.slice(4)).toEqual([0, 0])
    expect(event.defaultPrevented).toBe(true)
    wrapper.unmount()
  })

  /**
   * Pinch wheel deltas attempt to exceed both permitted zoom limits. The
   * resulting canvas zoom must remain within the minimum and maximum values for
   * each direction.
   */
  it('捏合缩放保持 0.2 到 3 的边界', () => {
    const wrapper = mountCanvas()
    fabricState.main.setViewportTransform([3, 0, 0, 3, 0, 0])
    emitWheel({ deltaY: -100, ctrlKey: true })
    expect(fabricState.main.getZoom()).toBe(3)

    fabricState.main.setViewportTransform([0.2, 0, 0, 0.2, 0, 0])
    emitWheel({ deltaY: 100, ctrlKey: true })
    expect(fabricState.main.getZoom()).toBe(0.2)
    wrapper.unmount()
  })

  /**
   * A two-finger gesture changes touch distance and midpoint after its initial
   * capture. The viewport must scale and translate around the captured scene
   * anchor while consuming movement.
   */
  it('移动端双指缩放以手势中点下的场景点为锚并同步平移', () => {
    const wrapper = mountCanvas()
    fabricState.viewportPoint = { x: 150, y: 100 }
    const container = wrapper.find('.dot-grid').element
    container.dispatchEvent(
      makeTouchEvent('touchstart', [
        { clientX: 100, clientY: 100 },
        { clientX: 200, clientY: 100 },
      ]),
    )
    const move = makeTouchEvent('touchmove', [
      { clientX: 100, clientY: 100 },
      { clientX: 220, clientY: 100 },
    ])
    container.dispatchEvent(move)

    expect(fabricState.main.getZoom()).toBeCloseTo(1.2)
    expect(fabricState.main.viewportTransform.slice(4)).toEqual([-20, -20])
    expect(move.defaultPrevented).toBe(true)
    wrapper.unmount()
  })

  /**
   * An uploaded image becomes the selected inpaint anchor after placement. Its
   * runtime outline must use matching left-top coordinates and displayed
   * dimensions rather than a centered origin.
   */
  it('局部重绘选中图片时，锚点描边与图片左上角对齐', async () => {
    const wrapper = mount(CreativeCanvas, {
      props: { operation: 'inpaint' },
      global: { stubs: { CropperModal: true, Icon: true } },
    })
    const source = new File(['image'], 'source.png', { type: 'image/png' })
    await (
      wrapper.vm as unknown as {
        addUploadedImage: (blob: Blob) => Promise<void> // exposed source upload operation
      }
    ).addUploadedImage(source)
    const image = fabricState.images[0]
    fabricState.main.emit('selection:created', { selected: [image] })
    await flushPromises()

    const outline = fabricState.main.objects.find(
      (object: {
        data?: Record<string, unknown> // custom scene object metadata
      }) => object.data?.kind === 'anchor-outline',
    )
    expect(outline).toMatchObject({
      left: image.left,
      top: image.top,
      width: image.width * image.scaleX,
      height: image.height * image.scaleY,
      originX: 'left',
      originY: 'top',
    })
    wrapper.unmount()
  })
})
